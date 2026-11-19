-- Image names are immutable platform approvals. The host separately reports
-- the digest pairs actually installed and verified by its runtime.
CREATE TABLE system_images (
  id text PRIMARY KEY, kernel_digest text NOT NULL, initrd_digest text NOT NULL,
  approved_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE deployment_hosts (
  host_id text PRIMARY KEY REFERENCES worker_hosts(host_id),
  max_active integer NOT NULL CHECK (max_active>0),
  vcpus integer NOT NULL CHECK (vcpus>0),
  memory_mib bigint NOT NULL CHECK (memory_mib>0),
  uid_slots integer NOT NULL CHECK (uid_slots>0),
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE host_system_images (
  host_id text REFERENCES deployment_hosts(host_id), kernel_digest text, initrd_digest text,
  PRIMARY KEY (host_id,kernel_digest,initrd_digest)
);
CREATE TABLE agent_template_revisions (
  tenant_id text REFERENCES organizations(id), name text, revision integer CHECK(revision>0),
  spec jsonb NOT NULL, published_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,name,revision)
);
CREATE TABLE agent_deployments (
  id text PRIMARY KEY, tenant_id text NOT NULL, template_name text NOT NULL, revision integer NOT NULL,
  host_id text NOT NULL REFERENCES worker_hosts(host_id), requested_count integer NOT NULL CHECK(requested_count>0),
  active_count integer NOT NULL CHECK(active_count BETWEEN 0 AND requested_count),
  resources jsonb NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  applied_at timestamptz,
  UNIQUE (tenant_id,id), FOREIGN KEY(tenant_id,template_name,revision) REFERENCES agent_template_revisions
);
CREATE TABLE agent_deployment_members (
  tenant_id text NOT NULL, deployment_id text NOT NULL, ordinal integer NOT NULL CHECK(ordinal>0), agent_id text NOT NULL UNIQUE,
  PRIMARY KEY(deployment_id,ordinal),
  FOREIGN KEY(tenant_id,deployment_id) REFERENCES agent_deployments(tenant_id,id)
);
ALTER TABLE agent_specs ADD COLUMN system_image text REFERENCES system_images(id);
CREATE TABLE agent_pools (
  id text PRIMARY KEY, tenant_id text NOT NULL, name text NOT NULL, deployment_id text NOT NULL,
  UNIQUE(tenant_id,id), UNIQUE(tenant_id,name), UNIQUE(tenant_id,deployment_id),
  FOREIGN KEY(tenant_id,deployment_id) REFERENCES agent_deployments(tenant_id,id)
);
CREATE TABLE agent_pool_members (
  tenant_id text NOT NULL, pool_id text NOT NULL, agent_id text NOT NULL UNIQUE,
  PRIMARY KEY(tenant_id,pool_id,agent_id),
  FOREIGN KEY(tenant_id,pool_id) REFERENCES agent_pools(tenant_id,id)
);
CREATE VIEW available_pool_members AS
 SELECT m.* FROM agent_pool_members m JOIN agents a ON (a.tenant_id,a.id)=(m.tenant_id,m.agent_id)
 WHERE a.phase IN ('LIVE','PROVISIONING') AND NOT EXISTS
 (SELECT FROM agent_assignments s WHERE (s.tenant_id,s.agent_id)=(m.tenant_id,m.agent_id) AND s.status='active');
CREATE VIEW agent_pool_inventory AS SELECT * FROM available_pool_members;
ALTER TABLE worker_jobs ADD COLUMN capacity_wait boolean NOT NULL DEFAULT false;
