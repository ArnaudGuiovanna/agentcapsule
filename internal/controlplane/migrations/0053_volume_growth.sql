CREATE TABLE deployment_audit (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES organizations(id), actor text NOT NULL, action text NOT NULL,
 target text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX deployment_audit_feed ON deployment_audit(tenant_id,created_at,id);
CREATE INDEX deployment_audit_retention ON deployment_audit(created_at);
CREATE TABLE agent_volume_growth (
 id text PRIMARY KEY, tenant_id text NOT NULL, agent_id text NOT NULL, host_id text NOT NULL REFERENCES worker_hosts(host_id),
 old_mib integer NOT NULL, target_mib integer NOT NULL CHECK(target_mib BETWEEN 64 AND 32768 AND target_mib>old_mib),
 archive_id text NOT NULL UNIQUE, restore_id text NOT NULL UNIQUE,
 stage text NOT NULL DEFAULT 'pending' CHECK(stage IN ('pending','capturing','restoring','succeeded','refused')),
 reason text NOT NULL DEFAULT '', attempted_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id)
);
CREATE UNIQUE INDEX one_volume_growth ON agent_volume_growth(agent_id) WHERE stage IN ('pending','capturing','restoring');
ALTER TABLE agent_specs ADD COLUMN reserved_growth_mib integer NOT NULL DEFAULT 0 CHECK (reserved_growth_mib>=0 AND volume_mib+reserved_growth_mib<=32768);
ALTER TABLE volume_restores ADD COLUMN grow_to_mib integer NOT NULL DEFAULT 0;
