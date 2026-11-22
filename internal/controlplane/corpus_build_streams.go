package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

var corpusFileStep = regexp.MustCompile(`^file-[1-9][0-9]{0,8}$`)

// ReadCorpusBuildStream returns the build's state and file progress in one
// read-only snapshot. The tenant's review permission grants access to file
// names. A build never grants access to its private builder invocation.
func (c *AgentCatalog) ReadCorpusBuildStream(ctx context.Context, p Principal, id string, attempt int, after int64, limit int) (OutputStreamView, error) {
	var out OutputStreamView
	if !validOrganizationText(id, 100) || attempt < 0 || after < 0 || limit < 1 || limit > 64 {
		return out, ErrInput
	}
	base, err := c.accounts.store.beginWithOptions(ctx, false, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	tx := snapshotTx{Tx: base}
	defer rollback(tx)
	if err = corpusPermission(ctx, tx, p, authorization.ManageCorpus); err != nil {
		return out, err
	}
	var op, agent, requester string
	err = tx.QueryRow(ctx, `SELECT b.state,coalesce(b.error_code,''),coalesce(i.operation_id,''),coalesce(a.id,''),coalesce(a.builder_principal,''),
       coalesce(i.attempt,1),coalesce(s.last_seq,0),coalesce(s.truncated,false)
       FROM corpus_builds b
       LEFT JOIN agents a ON a.id=b.builder_agent_id AND a.tenant_id=b.tenant_id AND a.kind='corpus_builder'
       LEFT JOIN platform_operations o ON o.id=b.conversion_invocation_id AND o.agent_id=a.id AND o.requested_by_principal_id=a.builder_principal AND o.kind='instruction'
       LEFT JOIN owner_instructions i ON i.operation_id=o.id
       LEFT JOIN invocation_streams s ON s.operation_id=i.operation_id AND s.attempt=i.attempt
       WHERE b.id=$1 AND b.tenant_id=$2`, id, p.TenantID).Scan(&out.State, &out.ErrorCode, &op, &agent, &requester, &out.Attempt, &out.LastSeq, &out.Truncated)
	if errors.Is(err, pgx.ErrNoRows) {
		return OutputStreamView{}, ErrNotFound
	}
	if err != nil {
		return OutputStreamView{}, err
	}
	if op != "" {
		if c.transit == nil {
			return OutputStreamView{}, ErrTransitKey
		}
		if attempt != out.Attempt {
			after = 0
		}
		out.Chunks, err = c.readStreamChunks(ctx, tx, op, agent, requester, out.Attempt, after, limit)
		if err != nil {
			return OutputStreamView{}, err
		}
		for i := range out.Chunks {
			var frames []capsuleprotocol.OutputFrame
			raw := out.Chunks[i].Frames
			err = json.Unmarshal(raw, &frames)
			clear(raw)
			if err != nil {
				return OutputStreamView{}, ErrTransitPayload
			}
			progress := frames[:0]
			for _, f := range frames {
				if f.Type == "step" && corpusFileStep.MatchString(f.Step) {
					progress = append(progress, capsuleprotocol.OutputFrame{Type: f.Type, Seq: f.Seq, Step: f.Step, State: f.State, Label: f.Label})
				}
			}
			out.Chunks[i].Frames, err = json.Marshal(progress)
			if err != nil {
				return OutputStreamView{}, err
			}
		}
	}
	return out, commit(ctx, tx)
}
