CREATE TABLE agent_rollouts (
 id text PRIMARY KEY, tenant_id text NOT NULL, deployment_id text NOT NULL,
 template_name text NOT NULL, revision integer NOT NULL, release_id text REFERENCES harness_releases(id),
 max_unavailable integer NOT NULL CHECK (max_unavailable BETWEEN 1 AND 1000),
 status text NOT NULL CHECK(status IN ('running','paused','completed')),
 reason text NOT NULL DEFAULT '', created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,template_name,revision) REFERENCES agent_template_revisions,
 FOREIGN KEY(tenant_id,deployment_id) REFERENCES agent_deployments(tenant_id,id)
);
CREATE UNIQUE INDEX one_open_rollout ON agent_rollouts(deployment_id) WHERE status<>'completed';
CREATE TABLE agent_rollout_steps (
 rollout_id text REFERENCES agent_rollouts(id), agent_id text REFERENCES agents(id), wave integer NOT NULL,
 stage text NOT NULL CHECK(stage IN ('pending','draining','validating','verified','complete')),
 keep_running boolean, observed_generation bigint, observed_vm text,
 PRIMARY KEY(rollout_id,agent_id)
);
CREATE INDEX rollout_work ON agent_rollout_steps(rollout_id,wave,agent_id) WHERE stage<>'complete';
CREATE UNIQUE INDEX one_agent_maintenance ON agent_rollout_steps(agent_id) WHERE stage IN ('draining','validating','verified');
ALTER TABLE agent_specs ADD COLUMN template_grant_id text REFERENCES llm_alias_grants(id);
