package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

// The output stream of a working invocation (ADR 022 §5). While an
// invocation works, its agent's current boot may stream deltas and steps; the
// worker coalesces them into chunks. The opening binds the stream to the
// invocation's current attempt, and each chunk's transaction checks again,
// under the locks of CompleteInvocationFromVM, what the opening checked: the
// stream lives in the worker's memory, and an outcome's transaction cannot
// close it (model invocation_completion.qnt). Deltas are never an outcome:
// nothing here writes the status, the key or the result.

// StreamLimits bound an attempt's output stream and the life of its chunks.
type StreamLimits struct {
	// MaxBytes and MaxFrames bound the frames stored for one attempt, in
	// their encoded size and in number.
	MaxBytes  int64
	MaxFrames int
	// Retention is how long chunks are kept after the invocation's outcome.
	Retention time.Duration
}

// DefaultStreamLimits are output_streams' defaults.
var DefaultStreamLimits = StreamLimits{MaxBytes: 2 << 20, MaxFrames: 4096, Retention: 10 * time.Minute}

// Valid holds the bounds of the worker's settings.
func (l StreamLimits) Valid() bool {
	return l.MaxBytes >= 64<<10 && l.MaxBytes <= 16<<20 && l.MaxFrames >= 64 && l.MaxFrames <= 65536 &&
		l.Retention >= time.Minute && l.Retention <= 24*time.Hour
}

// StreamOpening is an output stream bound to its invocation's attempt.
type StreamOpening struct {
	Attempt int
	// LastSeq is the last seq stored for the attempt, 0 if none.
	LastSeq int64
	// Closing is set when the stream closes as soon as it opens:
	// StreamReset (the named attempt is no longer current) or
	// StreamTruncated (the attempt reached its limits).
	Closing string
}

// StreamAppend is what one chunk's transaction did.
type StreamAppend struct {
	// LastSeq is the attempt's last stored seq after the transaction.
	LastSeq int64
	// Stored counts the frames this transaction stored.
	Stored int
	// Reason is why the stream closes, or "": a closed reason of
	// capsuleprotocol, or StreamCanceled.
	Reason string
	// FirstDelta is set when this chunk stored the attempt's first delta:
	// the time since the invocation answered working.
	FirstDelta time.Duration
}

// streamState is an invocation as the stream sees it.
type streamState struct {
	status, errorCode, requester string
	working, keyed, due          bool
	attempt                      int
}

const streamStateSelect = `SELECT o.status,o.error_code,coalesce(o.owner_user_id,o.requested_by_principal_id,''),
        i.working_since IS NOT NULL,i.completion_key IS NOT NULL,coalesce(i.result_due_at<=clock_timestamp(),false),i.attempt
    FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
    WHERE i.operation_id=$1 AND o.agent_id=$2 AND o.kind='instruction'`

func scanStreamState(row pgx.Row) (streamState, error) {
	var s streamState
	err := row.Scan(&s.status, &s.errorCode, &s.requester, &s.working, &s.keyed, &s.due, &s.attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// closeReason is why a stream of attempt must stop, or "" while the
// invocation works on that attempt. A newer attempt wins: after a rerun the
// invocation is queued again, which is not an outcome.
func (s streamState) closeReason(attempt int) string {
	switch {
	case s.attempt != attempt:
		return capsuleprotocol.StreamReset
	case s.status == "CANCELED":
		return capsuleprotocol.StreamCanceled
	case s.status == "FAILED" && s.errorCode == "work_timeout":
		return capsuleprotocol.StreamExpired
	case s.status != "RUNNING" || !s.working || s.keyed:
		return capsuleprotocol.StreamTerminal
	case s.due:
		return capsuleprotocol.StreamExpired
	}
	return ""
}

// revokedBoot reports a caller that is no longer its agent's current boot.
func revokedBoot(err error) bool {
	return errors.Is(err, ErrPlacement) || errors.Is(err, ErrStoreEnrollment) || errors.Is(err, pgx.ErrNoRows)
}

func validStreamOperation(op string) bool { return op != "" && len(op) <= 100 }

// Connect opens a connection outside the pool, with the pool's settings:
// the one a notification hub listens on (pgnotify, ADR 022 §6.5).
func (s *Store) Connect(ctx context.Context) (*pgx.Conn, error) {
	return pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
}

// OpenOutputStreamFromVM opens the output stream of a working invocation
// (ADR 022 §5.4): the caller is its agent's current boot, the invocation is
// working and before its due time. attempt is 0 at a first opening; a
// harness that opens again names the attempt it was given, and a stale one
// opens and closes at once (StreamReset).
func (t *Transit) OpenOutputStreamFromVM(ctx context.Context, caller VMCaller, op string, attempt int) (StreamOpening, error) {
	var out StreamOpening
	if caller.AgentID == "" || !validStreamOperation(op) || attempt < 0 {
		return out, ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return out, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return out, err
	}
	s, err := scanStreamState(tx.QueryRow(ctx, streamStateSelect+` FOR UPDATE OF i,o`, op, caller.AgentID))
	if err != nil {
		return out, err
	}
	switch {
	case !s.working:
		return out, ErrTransition // answered at delivery, not delivered, or queued again
	case s.status == "FAILED":
		return out, ErrExpired
	case s.status != "RUNNING" || s.keyed:
		return out, ErrTransition // canceled, or completed
	case s.due:
		return out, ErrExpired
	}
	if _, err = tx.Exec(ctx, `INSERT INTO invocation_streams(operation_id,attempt) VALUES($1,$2) ON CONFLICT (operation_id) DO NOTHING`, op, s.attempt); err != nil {
		return out, err
	}
	var bound int
	var truncated bool
	if err = tx.QueryRow(ctx, `SELECT attempt,last_seq,truncated FROM invocation_streams WHERE operation_id=$1 FOR UPDATE`, op).
		Scan(&bound, &out.LastSeq, &truncated); err != nil {
		return out, err
	}
	if bound != s.attempt {
		// Every new attempt resets the row (newAttempt); this one predates it.
		if err = dropStreamAttempts(ctx, tx, op, s.attempt); err != nil {
			return out, err
		}
		out.LastSeq, truncated = 0, false
	}
	out.Attempt = s.attempt
	switch {
	case attempt != 0 && attempt != s.attempt:
		out.Closing = capsuleprotocol.StreamReset
	case truncated:
		out.Closing = capsuleprotocol.StreamTruncated
	}
	return out, commit(ctx, tx)
}

// AppendOutputStreamFromVM commits one chunk of an open stream (ADR 022 §5.6)
// in its own transaction, under the opening's locks and in its order, after
// checking again the boot, the working state, the due time and the attempt.
// A refused check stores nothing and gives the stream's close reason. Past
// the attempt's limits, it stores the frames that fit and truncates the
// attempt. frames must follow each other from the attempt's next seq.
func (t *Transit) AppendOutputStreamFromVM(ctx context.Context, caller VMCaller, op string, attempt int, frames []capsuleprotocol.OutputFrame, limits StreamLimits) (StreamAppend, error) {
	var out StreamAppend
	if caller.AgentID == "" || !validStreamOperation(op) || attempt < 1 || len(frames) == 0 || !limits.Valid() {
		return out, ErrInput
	}
	encoded := make([][]byte, len(frames))
	for i, f := range frames {
		b, err := f.Encode()
		if err != nil || i > 0 && f.Seq != frames[i-1].Seq+1 {
			return out, ErrInput
		}
		encoded[i] = b
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return out, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); revokedBoot(err) {
		out.Reason = capsuleprotocol.StreamRevoked
		return out, nil
	} else if err != nil {
		return out, err
	}
	s, err := scanStreamState(tx.QueryRow(ctx, streamStateSelect+` FOR UPDATE OF i,o`, op, caller.AgentID))
	if errors.Is(err, ErrNotFound) {
		out.Reason = capsuleprotocol.StreamRevoked
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if out.Reason = s.closeReason(attempt); out.Reason != "" {
		return out, nil
	}
	var bound, count int
	var size int64
	var truncated, firstDelta bool
	err = tx.QueryRow(ctx, `SELECT attempt,last_seq,frames,bytes,truncated,first_delta_at IS NULL FROM invocation_streams
        WHERE operation_id=$1 FOR UPDATE`, op).Scan(&bound, &out.LastSeq, &count, &size, &truncated, &firstDelta)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && bound != attempt {
		out.Reason = capsuleprotocol.StreamReset
		return out, nil
	}
	if err != nil {
		return out, err
	}
	switch {
	case truncated:
		out.Reason = capsuleprotocol.StreamTruncated
		return out, nil
	case frames[0].Seq != out.LastSeq+1:
		out.Reason = capsuleprotocol.StreamInvalid
		return out, nil
	}
	take, bytes, delta := 0, int64(0), false
	for _, b := range encoded {
		if count+take+1 > limits.MaxFrames || size+bytes+int64(len(b)) > limits.MaxBytes {
			truncated = true
			break
		}
		delta = delta || frames[take].Type == "delta"
		bytes += int64(len(b))
		take++
	}
	if take > 0 {
		chunk, err := capsuleprotocol.EncodeOutputChunk(frames[:take])
		if err != nil {
			return out, err
		}
		first := frames[0].Seq
		last := frames[take-1].Seq
		payload, err := t.putOwned(ctx, tx, "stream_chunk", fmt.Sprintf("%s/%d/%d", op, attempt, first), []string{caller.AgentID},
			map[string]string{caller.AgentID: s.requester}, chunk)
		clear(chunk)
		if err != nil {
			return out, err
		}
		// The purge deletes the chunk soon after the outcome; this date is
		// only a bound, in case nothing else does (ADR 022 §5.8).
		if _, err = tx.Exec(ctx, `UPDATE transit_payloads p SET delivered_at=clock_timestamp(),
            purge_after=greatest(i.result_due_at,clock_timestamp())+$3::bigint*interval '1 microsecond'
            FROM owner_instructions i WHERE p.id=$1 AND i.operation_id=$2`, payload.ID, op, limits.Retention.Microseconds()); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO invocation_stream_chunks(operation_id,attempt,first_seq,last_seq,payload_id) VALUES($1,$2,$3,$4,$5)`,
			op, attempt, first, last, payload.ID); err != nil {
			return out, err
		}
		out.LastSeq, out.Stored = last, take
	}
	var micros *int64
	if err = tx.QueryRow(ctx, `UPDATE invocation_streams s SET last_seq=$2,frames=frames+$3,bytes=bytes+$4,truncated=$5,
            first_delta_at=CASE WHEN $6 AND first_delta_at IS NULL THEN clock_timestamp() ELSE first_delta_at END,updated_at=clock_timestamp()
        FROM owner_instructions i WHERE s.operation_id=$1 AND i.operation_id=$1
        RETURNING CASE WHEN $6 AND $7 THEN (extract(epoch FROM s.first_delta_at-i.working_since)*1000000)::bigint END`,
		op, out.LastSeq, take, bytes, truncated, delta, firstDelta).Scan(&micros); err != nil {
		return out, err
	}
	if err = commit(ctx, tx); err != nil {
		return StreamAppend{}, err
	}
	if micros != nil && *micros >= 0 {
		out.FirstDelta = time.Duration(*micros) * time.Microsecond
	}
	if truncated {
		out.Reason = capsuleprotocol.StreamTruncated
	}
	return out, nil
}

// OutputStreamSignal reads, without a lock, why an open stream must close
// now: its invocation's outcome, a newer attempt, a passed due time, or a
// boot no longer current. "" while the invocation works on attempt. The
// worker reads it at each notification of the stream's invocation.
func (s *Store) OutputStreamSignal(ctx context.Context, caller VMCaller, op string, attempt int) (string, error) {
	if caller.AgentID == "" || !validStreamOperation(op) || attempt < 1 {
		return "", ErrInput
	}
	var current bool
	st, err := scanStreamState(s.pool.QueryRow(ctx, streamStateSelect, op, caller.AgentID))
	if errors.Is(err, ErrNotFound) {
		return capsuleprotocol.StreamRevoked, nil
	}
	if err != nil {
		return "", err
	}
	if reason := st.closeReason(attempt); reason != "" {
		return reason, nil
	}
	if err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents a JOIN agent_placements p ON p.agent_id=a.id
        WHERE a.id=$1 AND a.phase='LIVE' AND p.host_id=$2 AND p.generation=$3 AND p.vm_id=$4 AND p.state='RUNNING' AND NOT p.fence_only)`,
		caller.AgentID, caller.HostID, int64(caller.Generation), caller.VMID).Scan(&current); err != nil {
		return "", err
	}
	if !current {
		return capsuleprotocol.StreamRevoked, nil
	}
	return "", nil
}

// newAttempt starts the next attempt of invocation op: a restore's rerun or
// a dead letter's replay, in the transaction that clears working_since. The
// previous attempts' chunks and their payloads go at once, and the stream's
// state row starts again; a stream of an old attempt that is still open is
// refused at its next chunk (StreamReset).
func newAttempt(ctx context.Context, tx pgx.Tx, op string) error {
	var attempt int
	if err := tx.QueryRow(ctx, `UPDATE owner_instructions SET attempt=attempt+1 WHERE operation_id=$1 RETURNING attempt`, op).Scan(&attempt); err != nil {
		return err
	}
	return dropStreamAttempts(ctx, tx, op, attempt)
}

// dropStreamAttempts deletes op's chunks of other attempts than current, and
// resets its state row to current.
func dropStreamAttempts(ctx context.Context, tx pgx.Tx, op string, current int) error {
	rows, err := tx.Query(ctx, `DELETE FROM invocation_stream_chunks WHERE operation_id=$1 AND attempt<>$2 RETURNING payload_id`, op, current)
	if err != nil {
		return err
	}
	payloads, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if err = deleteChunkPayloads(ctx, tx, payloads); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE invocation_streams SET attempt=$2,last_seq=0,frames=0,bytes=0,truncated=false,first_delta_at=NULL,
        updated_at=clock_timestamp() WHERE operation_id=$1`, op, current)
	return err
}

// deleteChunkPayloads deletes the payloads of deleted chunks, and their
// parties. Chunks keep no tombstone: their life is short and bounded.
func deleteChunkPayloads(ctx context.Context, tx pgx.Tx, payloads []string) error {
	if len(payloads) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM transit_parties WHERE payload_id=ANY($1)`, payloads); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM transit_payloads WHERE id=ANY($1) AND kind='stream_chunk'`, payloads)
	return err
}

// PurgeStreamChunks deletes, at most limit at a time, the chunks and their
// payloads of invocations whose outcome is older than retention, of agents
// being deleted, and of payloads past their purge date (ADR 022 §5.11).
// Reruns and replays delete theirs at once. now is the database clock when nil.
func (s *Store) PurgeStreamChunks(ctx context.Context, now *time.Time, retention time.Duration, limit int) (int64, error) {
	if limit < 1 || limit > 1000 || retention < 0 {
		return 0, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `DELETE FROM invocation_stream_chunks WHERE (operation_id,attempt,first_seq) IN
        (SELECT c.operation_id,c.attempt,c.first_seq FROM invocation_stream_chunks c
          JOIN platform_operations o ON o.id=c.operation_id JOIN agents a ON a.id=o.agent_id
          JOIN transit_payloads p ON p.id=c.payload_id
          WHERE (o.status IN ('SUCCEEDED','FAILED','CANCELED') AND o.completed_at<=`+dbNow+`-$2::bigint*interval '1 microsecond')
            OR a.phase NOT IN ('LIVE','PROVISIONING') OR p.purge_after<=`+dbNow+`
          ORDER BY c.created_at LIMIT $3 FOR UPDATE OF c SKIP LOCKED)
        RETURNING payload_id`, nowArg(now), retention.Microseconds(), limit)
	if err != nil {
		return 0, err
	}
	payloads, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	if err = deleteChunkPayloads(ctx, tx, payloads); err != nil {
		return 0, err
	}
	return int64(len(payloads)), commit(ctx, tx)
}

// StreamChunk is one stored chunk of an output stream, opened: Frames is
// the JSON array of its frames, as the worker sealed it.
type StreamChunk struct {
	Attempt  int             `json:"attempt"`
	FirstSeq int64           `json:"first_seq"`
	LastSeq  int64           `json:"last_seq"`
	Frames   json.RawMessage `json:"frames"`
}

// OutputStreamView is what the requester of an invocation sees of its
// output stream: the invocation's state, its current attempt, the attempt's
// last stored seq and truncation, and its chunks after a position.
type OutputStreamView struct {
	// Status is the operation's status (PENDING, RUNNING, SUCCEEDED, FAILED,
	// CANCELED); Working is true while the agent works on it.
	Status    string        `json:"status"`
	Working   bool          `json:"working"`
	Attempt   int           `json:"attempt"`
	LastSeq   int64         `json:"last_seq"`
	Truncated bool          `json:"truncated"`
	Chunks    []StreamChunk `json:"chunks"`
}

// ReadOutputStream opens, for the principal who requested the invocation and
// only while that principal holds read_content on its agent, the chunks of
// the current attempt whose frames come after seq after, at most limit, in
// order. The rights are those of the result (instructionResultTenant), except
// that no result needs to exist. Anyone else gets ErrNotFound; a credential
// without agent:content:read, ErrForbidden.
func (c *AgentCatalog) ReadOutputStream(ctx context.Context, p Principal, op string, after int64, limit int) (OutputStreamView, error) {
	var out OutputStreamView
	if p.Kind != "tenant" || !validOrganizationText(op, 100) || after < 0 || limit < 1 || limit > 64 {
		return out, ErrInput
	}
	if c.transit == nil {
		return out, ErrTransitKey
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if _, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentContentRead); err != nil {
		return out, err
	}
	var agentID, phase string
	err = tx.QueryRow(ctx, `SELECT o.agent_id,a.phase,o.status,i.working_since IS NOT NULL AND i.completion_key IS NULL,i.attempt,
            coalesce(s.attempt=i.attempt AND s.truncated,false),CASE WHEN s.attempt=i.attempt THEN s.last_seq ELSE 0 END
        FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id JOIN agents a ON a.id=o.agent_id
        LEFT JOIN invocation_streams s ON s.operation_id=i.operation_id
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction'`, op, p.TenantID, p.ID).
		Scan(&agentID, &phase, &out.Status, &out.Working, &out.Attempt, &out.Truncated, &out.LastSeq)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && phase != "LIVE" {
		return OutputStreamView{}, ErrNotFound
	}
	if err != nil {
		return OutputStreamView{}, err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, agentID)
	if err != nil {
		return OutputStreamView{}, err
	}
	if !authorization.CanAccessAssignedAgent(tenantAccess(p), authorization.ReadAgentContent, toPermissions(perms)) {
		return OutputStreamView{}, ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT first_seq,last_seq,payload_id FROM invocation_stream_chunks
        WHERE operation_id=$1 AND attempt=$2 AND last_seq>$3 ORDER BY first_seq LIMIT $4`, op, out.Attempt, after, limit)
	if err != nil {
		return OutputStreamView{}, err
	}
	type stored struct {
		first, last int64
		payload     string
	}
	chunks, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (stored, error) {
		var s stored
		return s, r.Scan(&s.first, &s.last, &s.payload)
	})
	if err != nil {
		return OutputStreamView{}, err
	}
	out.Chunks = []StreamChunk{}
	defer func() {
		if err != nil {
			for _, ch := range out.Chunks {
				clear(ch.Frames)
			}
		}
	}()
	for _, ch := range chunks {
		var parties []transitParty
		if parties, err = payloadParties(ctx, tx, ch.payload); err != nil {
			return OutputStreamView{}, err
		}
		if !slices.Equal(parties, []transitParty{{agentID, p.ID}}) {
			err = ErrNotFound
			return OutputStreamView{}, err
		}
		var body []byte
		if body, err = c.transit.read(ctx, tx, ch.payload, parties); err != nil {
			return OutputStreamView{}, err
		}
		out.Chunks = append(out.Chunks, StreamChunk{Attempt: out.Attempt, FirstSeq: ch.first, LastSeq: ch.last, Frames: body})
	}
	if err = commit(ctx, tx); err != nil {
		return OutputStreamView{}, err
	}
	return out, nil
}
