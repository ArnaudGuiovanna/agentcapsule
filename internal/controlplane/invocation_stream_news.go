package controlplane

import "context"

// streamNewsQuery reads, in one statement, what ReadOutputStreamPage reads of
// requester $3's invocation $1 of a live agent of organization $2: its state,
// and the chunks of its current attempt after seq $5 (0 when the subscriber's
// attempt $4 is another), at most $6. A row per chunk; one row with no chunk
// when there is none.
const streamNewsQuery = `WITH v AS (
    SELECT o.agent_id,o.status,i.working_since IS NOT NULL AND i.completion_key IS NULL AS working,i.attempt,
           coalesce(s.attempt=i.attempt AND s.truncated,false) AS truncated,CASE WHEN s.attempt=i.attempt THEN s.last_seq ELSE 0 END AS last_seq,
           i.close_reason,i.run_at IS NOT NULL AND i.released_at IS NULL AS waiting,` + lostCondition + ` AS lost,
           CASE WHEN rerun.state='skipped' AND ` + lostCondition + ` THEN rerun.skip_reason ELSE o.error_code END AS error_code,
           EXISTS(SELECT 1 FROM transit_payloads t WHERE t.id=i.result_payload_id AND t.purged_at IS NULL
               AND (t.purge_after IS NULL OR t.purge_after>clock_timestamp())) AS result_available
      FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id JOIN agents a ON a.id=o.agent_id
      LEFT JOIN invocation_streams s ON s.operation_id=i.operation_id ` + rerunJoins + `
     WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction' AND a.phase='LIVE')
SELECT v.agent_id,v.status,v.working,v.attempt,v.truncated,v.last_seq,v.close_reason,v.waiting,v.lost,v.error_code,v.result_available,
       ch.first_seq,ch.last_seq,ch.id,ch.kind,ch.ref_id,ch.key_id,ch.content_hash,ch.ciphertext,ch.key_hash,ch.agents,ch.owners
  FROM v LEFT JOIN LATERAL (
    SELECT c.first_seq,c.last_seq,p.id,p.kind,p.ref_id,p.key_id,p.content_hash,p.ciphertext,k.key_hash,
           (SELECT array_agg(tp.agent_id ORDER BY tp.agent_id) FROM transit_parties tp WHERE tp.payload_id=p.id) AS agents,
           (SELECT array_agg(tp.owner_user_id ORDER BY tp.agent_id) FROM transit_parties tp WHERE tp.payload_id=p.id) AS owners
      FROM invocation_stream_chunks c JOIN transit_payloads p ON c.payload_id=p.id JOIN transit_keys k ON k.id=p.key_id
     WHERE c.operation_id=$1 AND c.attempt=v.attempt
       AND c.last_seq>CASE WHEN $4::int<>0 AND $4::int<>v.attempt THEN 0 ELSE $5::bigint END
       AND p.purged_at IS NULL AND (p.purge_after IS NULL OR p.purge_after>clock_timestamp())
     ORDER BY c.first_seq LIMIT $6) ch ON true
 ORDER BY ch.first_seq`

// ReadOutputStreamNews is ReadOutputStreamPage for a subscriber between two
// checks of its rights (P-11, ADR 022 §6.3): one statement on the pool, no
// transaction, the new chunks only. It still reads nothing but the
// principal's own invocation of a live agent of the principal's
// organization, and each chunk's binding is checked as there. The rights
// themselves, the credential's and read_content's, are not checked: the
// subscriber checks them with ReadOutputStreamPage every 10 seconds and at
// each change of the organization's policy.
func (c *AgentCatalog) ReadOutputStreamNews(ctx context.Context, p Principal, op string, attempt int, after int64, limit int) (OutputStreamView, error) {
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
	rows, err := c.accounts.store.pool.Query(ctx, streamNewsQuery, op, p.TenantID, p.ID, attempt, after, limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var agentID, closeReason string
	var waiting, lost, found bool
	var sealed []sealedChunk
	for rows.Next() {
		var first, last *int64
		var id, kind, ref, key *string
		var s sealedChunk
		if err = rows.Scan(&agentID, &out.Status, &out.Working, &out.Attempt, &out.Truncated, &out.LastSeq, &closeReason, &waiting, &lost,
			&out.ErrorCode, &out.ResultAvailable, &first, &last, &id, &kind, &ref, &key, &s.binding.Hash, &s.ciphertext, &s.keyHash,
			&s.agents, &s.owners); err != nil {
			return OutputStreamView{}, err
		}
		found = true
		if first == nil {
			continue
		}
		if last == nil || id == nil || kind == nil || ref == nil || key == nil {
			return OutputStreamView{}, ErrTransitPayload
		}
		s.firstSeq, s.lastSeq = *first, *last
		s.binding.ID, s.binding.Kind, s.binding.Reference, s.binding.KeyID = *id, *kind, *ref, *key
		sealed = append(sealed, s)
	}
	if err = rows.Err(); err != nil {
		return OutputStreamView{}, err
	}
	if !found {
		return OutputStreamView{}, ErrNotFound
	}
	out.State = invocationState(out.Status, closeReason, waiting, lost)
	out.Chunks = []StreamChunk{}
	for _, s := range sealed {
		ch, err := c.openStreamChunk(op, agentID, p.ID, out.Attempt, s)
		if err != nil {
			return OutputStreamView{}, err
		}
		out.Chunks = append(out.Chunks, ch)
	}
	return out, nil
}
