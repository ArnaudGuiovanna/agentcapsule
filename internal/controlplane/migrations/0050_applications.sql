-- Registration binds a client in a verified issuer to exactly one tenant.
-- The service principal is also the revocable authority for the integration.
CREATE TABLE applications (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    issuer text NOT NULL,
    audience text NOT NULL,
    client_id text NOT NULL,
    redirect_uris text[] NOT NULL,
    verification_keys jsonb NOT NULL,
    generation bigint NOT NULL DEFAULT 1,
    UNIQUE (issuer,client_id),
    UNIQUE (tenant_id,name),
    UNIQUE (tenant_id,id),
    FOREIGN KEY (tenant_id,id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE app_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    app_id text NOT NULL,
    spec jsonb NOT NULL,
    applied boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id,app_id,id),
    FOREIGN KEY (tenant_id,app_id) REFERENCES applications(tenant_id,id)
);

CREATE TABLE app_activations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    app_id text NOT NULL,
    policy_id text NOT NULL,
    principal_id text NOT NULL,
    team_id text,
    version bigint NOT NULL DEFAULT 1,
    disabled boolean NOT NULL DEFAULT false,
    retry_at timestamptz,
    UNIQUE (tenant_id,app_id,principal_id),
    UNIQUE (tenant_id,app_id,id),
    FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
    FOREIGN KEY (tenant_id,app_id,policy_id) REFERENCES app_policies(tenant_id,app_id,id)
);

CREATE INDEX app_activations_retry ON app_activations(retry_at) WHERE retry_at IS NOT NULL AND NOT disabled;

CREATE TABLE app_invitations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    app_id text NOT NULL,
    policy_id text NOT NULL,
    proof_hash bytea NOT NULL UNIQUE,
    email text NOT NULL,
    team_id text,
    expires_at timestamptz NOT NULL,
    activation_id text,
    FOREIGN KEY (tenant_id,app_id,policy_id) REFERENCES app_policies(tenant_id,app_id,id),
    FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
    FOREIGN KEY (tenant_id,app_id,activation_id) REFERENCES app_activations(tenant_id,app_id,id)
);

ALTER TABLE agent_assignments ADD COLUMN policy_id text REFERENCES app_policies(id);
ALTER TABLE team_memberships ADD COLUMN source_app_id text REFERENCES applications(id);
-- Distinct sources of the same permission must survive each other's revocation.
DROP INDEX agent_assignments_active_team;
DROP INDEX agent_assignments_active_principal;
CREATE UNIQUE INDEX agent_assignments_active_team ON agent_assignments(tenant_id,agent_id,team_id)
    WHERE status='active' AND team_id IS NOT NULL AND policy_id IS NULL;
CREATE UNIQUE INDEX agent_assignments_active_principal ON agent_assignments(tenant_id,agent_id,principal_id)
    WHERE status='active' AND principal_id IS NOT NULL AND policy_id IS NULL;
CREATE UNIQUE INDEX app_active_team_assignment ON agent_assignments(policy_id,agent_id,team_id)
    WHERE status='active' AND policy_id IS NOT NULL AND team_id IS NOT NULL;

CREATE TABLE app_personal_reservations (
    tenant_id text NOT NULL,
    agent_id text NOT NULL,
    principal_id text NOT NULL,
    policy_id text NOT NULL,
    slot text NOT NULL,
    PRIMARY KEY (tenant_id,agent_id),
    UNIQUE (tenant_id,principal_id,policy_id,slot),
    FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id),
    FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
    FOREIGN KEY (policy_id) REFERENCES app_policies(id)
);

CREATE OR REPLACE VIEW agent_pool_inventory AS
SELECT m.* FROM available_pool_members m WHERE NOT EXISTS
    (SELECT 1 FROM app_personal_reservations r WHERE (r.tenant_id,r.agent_id)=(m.tenant_id,m.agent_id));

CREATE TABLE application_audit (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES organizations(id),
    actor text NOT NULL,
    target text NOT NULL,
    action text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX application_audit_tenant ON application_audit(tenant_id,created_at,id);
