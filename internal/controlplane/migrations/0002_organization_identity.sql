-- Add the organization identity domain without assigning legacy owners to a
-- tenant or changing their encrypted historical bindings. Agent backfill and
-- activation of tenant-facing routes require a separate explicit migration.
CREATE TABLE organizations (
  id text PRIMARY KEY CHECK (id <> ''),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE principals (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  kind text NOT NULL CHECK (kind IN ('user','service')),
  issuer text,
  subject text,
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 100),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id,id),
  UNIQUE (tenant_id,issuer,subject),
  CHECK ((kind='user' AND issuer IS NOT NULL AND issuer<>'' AND subject IS NOT NULL AND subject<>'')
      OR (kind='service' AND issuer IS NULL AND subject IS NULL))
);

-- Exactly one administrative role per principal. Content permissions are
-- separate assignments; no administrative role implies a right to content.
CREATE TABLE memberships (
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('org_owner','org_admin','agent_operator','agent_user','auditor')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,principal_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE teams (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id,id)
);

CREATE TABLE team_memberships (
  tenant_id text NOT NULL,
  team_id text NOT NULL,
  principal_id text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,team_id,principal_id),
  FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);

CREATE INDEX principals_tenant_status ON principals(tenant_id,status,id);
CREATE INDEX teams_tenant_status ON teams(tenant_id,status,id);
CREATE INDEX team_memberships_principal ON team_memberships(tenant_id,principal_id,team_id);
