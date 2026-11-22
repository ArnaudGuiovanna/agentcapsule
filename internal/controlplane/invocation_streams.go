package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
	"github.com/jackc/pgx/v5"
)

// The output stream of a working invocation (ADR 022 §5). While an
// invocation works, its agent's current boot may stream deltas and steps; the
// worker coalesces them into chunks. The opening binds the stream to the
// invocation's current attempt, and each chunk's transaction checks again
// what the opening checked, under the locks that every end of the stream
// takes: the placement's (a boot that ends) and the invocation's rows (an
// outcome, a cancellation, an expiry, a rerun). The stream lives in the
// worker's memory, and an outcome's transaction cannot close it (model
// invocation_completion.qnt). Deltas are never an outcome: nothing here
// writes the status, the key or the result.

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
		return wire.StreamReset
	case s.status == "CANCELED":
		return wire.StreamCanceled
	case s.status == "FAILED" && s.errorCode == "work_timeout":
		return wire.StreamExpired
	case s.status != "RUNNING" || !s.working || s.keyed:
		return wire.StreamTerminal
	case s.due:
		return wire.StreamExpired
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
		out.Closing = wire.StreamReset
	case truncated:
		out.Closing = wire.StreamTruncated
	}
	return out, commit(ctx, tx)
}

// AppendOutputStreamFromVM commits one chunk of an open stream (ADR 022 §5.6)
// in its own transaction, after checking again the boot, the working state,
// the due time and the attempt. It takes the opening's locks but the agent
// row's (P-11): the placement's, then the invocation's rows and its stream's,
// in that order, so a chunk no longer waits for every other transaction of
// its agent, nor they for it. The agent's deletion cancels the invocation in
// its transaction before it purges the agent's content, so a chunk commits
// before it, and is purged with the rest, or sees the cancellation. A refused
// check stores nothing and gives the stream's close reason. Past the
// attempt's limits, it stores the frames that fit and truncates the attempt.
// frames must follow each other from the attempt's next seq.
func (t *Transit) AppendOutputStreamFromVM(ctx context.Context, caller VMCaller, op string, attempt int, frames []wire.OutputFrame, limits StreamLimits) (StreamAppend, error) {
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
	agents, err := streamAgent(ctx, tx, caller.AgentID)
	if err != nil {
		return out, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); revokedBoot(err) {
		out.Reason = wire.StreamRevoked
		return out, nil
	} else if err != nil {
		return out, err
	}
	s, err := scanStreamState(tx.QueryRow(ctx, streamStateSelect+` FOR UPDATE OF i,o`, op, caller.AgentID))
	if errors.Is(err, ErrNotFound) {
		out.Reason = wire.StreamRevoked
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
		out.Reason = wire.StreamReset
		return out, nil
	}
	if err != nil {
		return out, err
	}
	switch {
	case truncated:
		out.Reason = wire.StreamTruncated
		return out, nil
	case frames[0].Seq != out.LastSeq+1:
		out.Reason = wire.StreamInvalid
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
		chunk, err := wire.EncodeOutputChunk(frames[:take])
		if err != nil {
			return out, err
		}
		first := frames[0].Seq
		last := frames[take-1].Seq
		payload, err := t.putChunk(ctx, tx, fmt.Sprintf("%s/%d/%d", op, attempt, first), agents[caller.AgentID], s.requester, chunk)
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
		out.Reason = wire.StreamTruncated
	}
	return out, nil
}

// streamAgent reads agent id's row as lockAgents does, without its lock: a
// chunk's transaction serializes through its placement and its invocation's
// rows instead (AppendOutputStreamFromVM).
func streamAgent(ctx context.Context, tx pgx.Tx, id string) (map[string]agent, error) {
	var a agent
	err := tx.QueryRow(ctx, `SELECT id, coalesce(owner_user_id,''), phase, inbound_mode, discoverable, coalesce(tenant_id,''), kind
        FROM agents WHERE id=$1`, id).Scan(&a.ID, &a.Owner, &a.Phase, &a.Mode, &a.Visible, &a.Tenant, &a.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return map[string]agent{}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]agent{a.ID: a}, nil
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
		return wire.StreamRevoked, nil
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
		return wire.StreamRevoked, nil
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
	State           string        `json:"state"`
	ErrorCode       string        `json:"error_code,omitempty"`
	ResultAvailable bool          `json:"result_available"`
	Status          string        `json:"status"`
	Working         bool          `json:"working"`
	Attempt         int           `json:"attempt"`
	LastSeq         int64         `json:"last_seq"`
	Truncated       bool          `json:"truncated"`
	Chunks          []StreamChunk `json:"chunks"`
}

// ReadOutputStream opens, for the principal who requested the invocation and
// only while that principal holds read_content on its agent, the chunks of
// the current attempt whose frames come after seq after, at most limit, in
// order. The rights are those of the result (instructionResultTenant), except
// that no result needs to exist. Anyone else gets ErrNotFound; a credential
// without agent:content:read, ErrForbidden.
func (c *AgentCatalog) ReadOutputStream(ctx context.Context, p Principal, op string, after int64, limit int) (OutputStreamView, error) {
	return c.ReadOutputStreamPage(ctx, p, op, 0, after, limit)
}

// snapshotTx is used only by read-only REPEATABLE READ projections. They see
// authority and content at the same snapshot. Mutating callers keep all the
// normal row locks until commit.
type snapshotTx struct{ pgx.Tx }

func authorityLock(tx pgx.Tx, clause string) string {
	if _, snapshot := tx.(snapshotTx); snapshot {
		return ""
	}
	return clause
}

// ReadOutputStreamPage reads state, rights and sealed frames at one database
// snapshot. A cursor from another attempt starts at its replacement's first
// frame. The caller never holds a connection while writing to the subscriber.
func (c *AgentCatalog) ReadOutputStreamPage(ctx context.Context, p Principal, op string, attempt int, after int64, limit int) (OutputStreamView, error) {
	var out OutputStreamView
	if !validOrganizationText(op, 100) || attempt < 0 || after < 0 || limit < 1 || limit > 64 {
		return out, ErrInput
	}
	if p.Kind != "tenant" {
		return out, ErrForbidden
	}
	if c.transit == nil {
		return out, ErrTransitKey
	}
	base, err := c.accounts.store.beginWithOptions(ctx, false, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	tx := snapshotTx{base}
	defer rollback(tx)
	if _, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentContentRead); err != nil {
		return out, err
	}
	var agentID, phase, closeReason string
	var waiting, lost bool
	err = tx.QueryRow(ctx, `SELECT o.agent_id,a.phase,o.status,i.working_since IS NOT NULL AND i.completion_key IS NULL,i.attempt,
            coalesce(s.attempt=i.attempt AND s.truncated,false),CASE WHEN s.attempt=i.attempt THEN s.last_seq ELSE 0 END,
            i.close_reason,i.run_at IS NOT NULL AND i.released_at IS NULL,`+lostCondition+`,
            CASE WHEN rerun.state='skipped' AND `+lostCondition+` THEN rerun.skip_reason ELSE o.error_code END,
            EXISTS(SELECT 1 FROM transit_payloads t WHERE t.id=i.result_payload_id AND t.purged_at IS NULL
                AND (t.purge_after IS NULL OR t.purge_after>clock_timestamp()))
        FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id JOIN agents a ON a.id=o.agent_id
        LEFT JOIN invocation_streams s ON s.operation_id=i.operation_id `+rerunJoins+`
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction'`, op, p.TenantID, p.ID).
		Scan(&agentID, &phase, &out.Status, &out.Working, &out.Attempt, &out.Truncated, &out.LastSeq, &closeReason, &waiting, &lost, &out.ErrorCode, &out.ResultAvailable)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && phase != "LIVE" {
		return OutputStreamView{}, ErrNotFound
	}
	if err != nil {
		return OutputStreamView{}, err
	}
	out.State = invocationState(out.Status, closeReason, waiting, lost)
	if err = mayReadAgentContent(ctx, tx, p, agentID); err != nil {
		return OutputStreamView{}, err
	}
	if attempt != 0 && attempt != out.Attempt {
		after = 0
	}
	out.Chunks, err = c.readStreamChunks(ctx, tx, op, agentID, p.ID, out.Attempt, after, limit)
	if err != nil {
		return OutputStreamView{}, err
	}
	return out, commit(ctx, tx)
}

// readStreamChunks authenticates each sealed chunk's writer and requester.
// Its caller establishes the reader's authority in the same snapshot.
func (c *AgentCatalog) readStreamChunks(ctx context.Context, tx pgx.Tx, op, agentID, requester string, attempt int, after int64, limit int) ([]StreamChunk, error) {
	rows, err := tx.Query(ctx, `SELECT c.first_seq,c.last_seq,p.id,p.kind,p.ref_id,p.key_id,p.content_hash,p.ciphertext,k.key_hash,
            (SELECT array_agg(tp.agent_id ORDER BY tp.agent_id) FROM transit_parties tp WHERE tp.payload_id=p.id),
            (SELECT array_agg(tp.owner_user_id ORDER BY tp.agent_id) FROM transit_parties tp WHERE tp.payload_id=p.id)
        FROM invocation_stream_chunks c JOIN transit_payloads p ON c.payload_id=p.id JOIN transit_keys k ON k.id=p.key_id
        WHERE c.operation_id=$1 AND c.attempt=$2 AND c.last_seq>$3 AND p.purged_at IS NULL
          AND (p.purge_after IS NULL OR p.purge_after>clock_timestamp()) ORDER BY c.first_seq LIMIT $4`, op, attempt, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (StreamChunk, error) {
		var sealed sealedChunk
		if err := row.Scan(&sealed.firstSeq, &sealed.lastSeq, &sealed.binding.ID, &sealed.binding.Kind, &sealed.binding.Reference,
			&sealed.binding.KeyID, &sealed.binding.Hash, &sealed.ciphertext, &sealed.keyHash, &sealed.agents, &sealed.owners); err != nil {
			return StreamChunk{}, err
		}
		return c.openStreamChunk(op, agentID, requester, attempt, sealed)
	})
}

// sealedChunk is a stored chunk as read, before its binding is checked.
type sealedChunk struct {
	firstSeq, lastSeq   int64
	binding             transitBinding
	ciphertext, keyHash []byte
	agents, owners      []string
}

// openStreamChunk authenticates a chunk's writer, requester and reference,
// then opens it.
func (c *AgentCatalog) openStreamChunk(op, agentID, requester string, attempt int, sealed sealedChunk) (StreamChunk, error) {
	ch := StreamChunk{Attempt: attempt, FirstSeq: sealed.firstSeq, LastSeq: sealed.lastSeq}
	b := sealed.binding
	b.Version, b.Parties = 1, []transitParty{{agentID, requester}}
	if !slices.Equal(sealed.agents, []string{agentID}) || !slices.Equal(sealed.owners, []string{requester}) {
		return ch, ErrNotFound
	}
	if b.Kind != "stream_chunk" || b.Reference != fmt.Sprintf("%s/%d/%d", op, attempt, ch.FirstSeq) {
		return ch, ErrTransitPayload
	}
	key, ok := c.transit.keys[b.KeyID]
	if !ok || !bytes.Equal(sealed.keyHash, key.hash[:]) {
		return ch, ErrTransitKey
	}
	body, err := openTransitPayload(key, b, sealed.ciphertext)
	ch.Frames = body
	return ch, err
}
