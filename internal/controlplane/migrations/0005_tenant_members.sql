-- Tenant receipts use a new authenticated envelope. Legacy http_receipts and
-- their associated data remain unchanged, including platform receipts.
CREATE TABLE tenant_http_receipts (
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  operation text NOT NULL CHECK (operation <> ''),
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response_status integer NOT NULL CHECK (response_status BETWEEN 200 AND 299),
  response_ciphertext bytea NOT NULL,
  aad_version integer NOT NULL CHECK (aad_version = 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '24 hours',
  PRIMARY KEY (tenant_id, principal_id, operation, key),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE tenant_member_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_principal_id text NOT NULL,
  target_principal_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('member.created','member.role_changed','member.revoked')),
  previous_role text NOT NULL,
  next_role text NOT NULL,
  changed boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,target_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX tenant_member_audit_tenant ON tenant_member_audit(tenant_id,created_at,id);
