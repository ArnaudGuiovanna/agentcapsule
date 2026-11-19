-- A deployment campaign targets one immutable template. A resize targets one
-- existing agent and changes only its CPU and memory.
ALTER TABLE agent_rollouts
  ALTER COLUMN deployment_id DROP NOT NULL,
  ALTER COLUMN template_name DROP NOT NULL,
  ALTER COLUMN revision DROP NOT NULL,
  ADD COLUMN target_agent text,
  ADD FOREIGN KEY (tenant_id,target_agent) REFERENCES agents(tenant_id,id),
  ADD COLUMN resize_vcpus integer CHECK (resize_vcpus BETWEEN 1 AND 8),
  ADD COLUMN resize_memory_mib integer CHECK (resize_memory_mib BETWEEN 128 AND 8192),
  ADD CONSTRAINT rollout_target CHECK (
    (deployment_id IS NOT NULL AND template_name IS NOT NULL AND revision IS NOT NULL
      AND target_agent IS NULL AND resize_vcpus IS NULL AND resize_memory_mib IS NULL)
    OR (deployment_id IS NULL AND template_name IS NULL AND revision IS NULL AND release_id IS NULL
      AND target_agent IS NOT NULL AND resize_vcpus IS NOT NULL AND resize_memory_mib IS NOT NULL AND max_unavailable=1)
  );
CREATE UNIQUE INDEX one_open_agent_resize ON agent_rollouts(target_agent)
  WHERE target_agent IS NOT NULL AND status<>'completed';

-- A rollout awaiting capacity may need a different resize to finish first.
ALTER TABLE agent_rollout_steps ADD COLUMN attempted_at timestamptz;
