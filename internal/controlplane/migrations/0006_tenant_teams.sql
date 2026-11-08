-- Existing teams and memberships retain their identities and state.
CREATE TABLE tenant_team_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_principal_id text NOT NULL,
  team_id text NOT NULL,
  target_principal_id text,
  action text NOT NULL CHECK (action IN ('team.created','team.disabled','team.member_added','team.member_revoked')),
  previous_status text NOT NULL CHECK (previous_status IN ('','active','disabled','revoked')),
  next_status text NOT NULL CHECK (next_status IN ('active','disabled','revoked')),
  changed boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action IN ('team.member_added','team.member_revoked')) = (target_principal_id IS NOT NULL)),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
  FOREIGN KEY (tenant_id,target_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX tenant_team_audit_tenant ON tenant_team_audit(tenant_id,created_at,id);
