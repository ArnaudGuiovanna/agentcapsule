package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

// EnsureCorpusBuilder provisions the tenant's private builder on its first
// guest phase. Restarting the worker observes the same provision operation.
func (s *Store) EnsureCorpusBuilder(ctx context.Context, j CorpusWork, harness HarnessReference, r AgentResources) (agentID, digest string, ready bool, err error) {
	if !r.valid() || !catalogName(harness.Name) || !catalogName(harness.Version) {
		err = ErrInput
		return
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return
	}
	defer rollback(tx)
	var tenant string
	err = tx.QueryRow(ctx, "SELECT tenant_id FROM corpus_builds"+corpusLease+" FOR UPDATE", j.ID, j.Token, j.Phase).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrLeaseLost
	}
	if err != nil {
		return
	}
	var release, image string
	err = tx.QueryRow(ctx, `SELECT r.id,r.artifact_digest,i.id FROM harness_releases r,system_images i JOIN host_system_images h USING(kernel_digest,initrd_digest)
 WHERE r.name=$1 AND r.version=$2 AND r.enabled AND (r.source='oci' AND r.base=$4 OR r.source='local-approved' AND r.artifact_digest=i.initrd_digest) AND h.host_id=$3 AND 'corpus.mount'=ANY(i.features) ORDER BY i.id LIMIT 1 FOR SHARE OF r,i,h`, harness.Name, harness.Version, j.Host, GuestBase2).Scan(&release, &digest, &image)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrRelease
	}
	if err != nil {
		return
	}
	agentID, ready, err = reserveCorpusGuest(ctx, tx, tenant, j.Host, release, image, "corpus_builder", "", r)
	if err != nil {
		return
	}
	if _, err = tx.Exec(ctx, "UPDATE corpus_builds SET builder_agent_id=$2,builder_digest=$3 WHERE id=$1", j.ID, agentID, digest); err != nil {
		return
	}
	err = commit(ctx, tx)
	return
}

func reserveCorpusGuest(ctx context.Context, tx pgx.Tx, tenant, targetHost, release, image, kind, enricher string, r AgentResources) (agentID string, ready bool, err error) {
	var phase, host, current string
	var capabilities = []string{}
	if kind == "corpus_builder" {
		capabilities = []string{"llm.invoke"}
	}
	err = tx.QueryRow(ctx, `SELECT a.id,a.phase,x.host_id,x.release_id FROM agents a JOIN agent_specs x ON x.agent_id=a.id WHERE a.tenant_id=$1 AND a.kind=$2 AND a.enricher_id IS NOT DISTINCT FROM nullif($3,'') FOR UPDATE OF a`, tenant, kind, enricher).Scan(&agentID, &phase, &host, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		agentID = newID("agt")
		requester, op := newID("svc"), newID("op")
		var room bool
		err = tx.QueryRow(ctx, `SELECT storage_limit_mib >= $2::bigint+(SELECT coalesce(sum(x.volume_mib+x.reserved_growth_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=$1 AND a.phase<>'DELETED') FROM worker_hosts WHERE host_id=$1 FOR UPDATE`, targetHost, r.DataVolumeMiB).Scan(&room)
		if err != nil {
			return
		}
		if !room {
			err = ErrStorageCapacity
			return
		}
		if err = refuseUnderDataPressure(ctx, tx, targetHost); err != nil {
			return
		}
		batch := &pgx.Batch{}
		batch.Queue("INSERT INTO principals(id,tenant_id,kind,display_name) VALUES($1,$2,'service',$3)", requester, tenant, kind)
		batch.Queue("INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,'agent_user')", tenant, requester)
		batch.Queue("INSERT INTO agents(id,tenant_id,kind,builder_principal,phase,enricher_id) VALUES($1,$2,$4,$3,'PROVISIONING',nullif($5,''))", agentID, tenant, requester, kind, enricher)
		batch.Queue(`INSERT INTO agent_specs(agent_id,name,release_id,host_id,system_image,vcpus,memory_mib,volume_mib,auto_start,idle_timeout_seconds,idle_policy_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,false,600,$9)`, agentID, kind+"-"+agentID, release, targetHost, image, r.VCPUs, r.MemoryMiB, r.DataVolumeMiB, requester)
		batch.Queue(`INSERT INTO agent_capability_policies(agent_id,allowed,updated_by) VALUES($1,$3,$2)`, agentID, requester, capabilities)
		batch.Queue(`INSERT INTO agent_assignments(id,tenant_id,agent_id,principal_id,permissions,created_by) VALUES($1,$2,$3,$4,ARRAY['invoke','read_content'],$4)`, newID("asg"), tenant, agentID, requester)
		batch.Queue(`INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind) VALUES($1,$2,$3,$4,1,'provision')`, op, requester, agentID, targetHost)
		batch.Queue(`INSERT INTO store_enrollments(agent_id,operation_id,volume_id) VALUES($1,$2,$3)`, agentID, op, newID("vol"))
		err = tx.SendBatch(ctx, batch).Close()
		if err != nil {
			return
		}
	} else if err != nil {
		return
	} else {
		if host != targetHost || current != release || phase != "LIVE" && phase != "PROVISIONING" {
			err = ErrRelease
			return
		}
		ready = phase == "LIVE"
	}
	return
}

// CorpusInvocation atomically submits a strictly bounded JSON part and stores
// its operation ID. A restarted worker observes the same private result.
func (c *AgentCatalog) CorpusInvocation(ctx context.Context, j CorpusWork, input json.RawMessage) (json.RawMessage, bool, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer rollback(tx)
	var agentID, requester, op string
	var micros int64
	err = tx.QueryRow(ctx, `SELECT b.builder_agent_id,a.builder_principal,coalesce(b.invocation_id,''),(extract(epoch FROM b.deadline_at-clock_timestamp())*1000000)::bigint
 FROM corpus_builds b JOIN agents a ON a.id=b.builder_agent_id
 WHERE b.id=$1 AND b.lease_token=$2 AND b.state=$3 AND b.lease_until>clock_timestamp() AND b.deadline_at>clock_timestamp() AND a.tenant_id=b.tenant_id AND a.kind='corpus_builder' FOR UPDATE OF b`, j.ID, j.Token, j.Phase).Scan(&agentID, &requester, &op, &micros)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrLeaseLost
	}
	if err != nil {
		return nil, false, err
	}
	return c.corpusGuestInvocation(ctx, tx, agentID, requester, op, j.Host, micros, input, func(op string) error {
		_, e := tx.Exec(ctx, "UPDATE corpus_builds SET invocation_id=$2 WHERE id=$1", j.ID, op)
		return e
	})
}
func (c *AgentCatalog) corpusGuestInvocation(ctx context.Context, tx pgx.Tx, agentID, requester, op, host string, micros int64, input json.RawMessage, save func(string) error) (json.RawMessage, bool, error) {
	var err error
	if op == "" {
		message := OwnerInstruction{Content: []capsuleprotocol.ContentPart{{Type: "json", JSON: capsuleprotocol.JSONValue(input)}}}
		if err = message.Validate(); err != nil {
			return nil, false, ErrInput
		}
		agents, err := lockAgents(ctx, tx, agentID)
		if err != nil {
			return nil, false, err
		}
		_, response, err := c.enqueueInstruction(ctx, tx, agents[agentID], agentID, host, requester, message, time.Duration(micros)*time.Microsecond, nil)
		if err != nil {
			return nil, false, err
		}
		op = response.(AgentCreation).OperationID
		if _, err = tx.Exec(ctx, `UPDATE owner_instructions SET work_timeout_seconds=least(86400,greatest(60,$2::bigint/1000000)) WHERE operation_id=$1`, op, micros); err != nil {
			return nil, false, err
		}
		if err = save(op); err != nil {
			return nil, false, err
		}
		return nil, false, commit(ctx, tx)
	}
	var status, payload string
	err = tx.QueryRow(ctx, `SELECT o.status,coalesce(i.result_payload_id,'') FROM platform_operations o JOIN owner_instructions i ON i.operation_id=o.id WHERE o.id=$1 AND o.agent_id=$2 AND o.requested_by_principal_id=$3`, op, agentID, requester).Scan(&status, &payload)
	if err != nil {
		return nil, false, err
	}
	if status == "FAILED" || status == "CANCELED" {
		return nil, true, ErrUnavailable
	}
	if status != "SUCCEEDED" {
		return nil, false, commit(ctx, tx)
	}
	parties, err := payloadParties(ctx, tx, payload)
	if err != nil {
		return nil, true, err
	}
	if len(parties) != 1 || parties[0].Owner != requester || parties[0].Agent != agentID {
		return nil, true, ErrTransitPayload
	}
	body, err := c.transit.read(ctx, tx, payload, parties)
	if err != nil {
		return nil, true, err
	}
	return body, true, commit(ctx, tx)
}
