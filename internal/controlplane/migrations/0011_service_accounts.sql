-- Tenant technical accounts (TEN-02). A technical account is a principal of kind
-- 'service' with one administrative role. Its credentials are separate opaque
-- tokens (acps_), stored only as SHA-256 hashes, bound to the human principal
-- that issued them so that offboarding or demotion revokes them.
CREATE TABLE service_tokens (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL,
  principal_id text NOT NULL,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32),
  expires_at timestamptz NOT NULL,
  issued_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoked_by text,
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,issued_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,revoked_by) REFERENCES principals(tenant_id,id)
);
CREATE INDEX service_tokens_principal ON service_tokens(tenant_id,principal_id,id);
CREATE INDEX service_tokens_issuer ON service_tokens(tenant_id,issued_by) WHERE revoked_at IS NULL;

CREATE TABLE tenant_service_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_principal_id text NOT NULL,
  service_principal_id text NOT NULL,
  token_id text REFERENCES service_tokens(id),
  action text NOT NULL CHECK (action IN ('service_account.created','service_account.disabled','token.issued','token.revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action IN ('token.issued','token.revoked')) = (token_id IS NOT NULL)),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,service_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX tenant_service_audit_tenant ON tenant_service_audit(tenant_id,created_at,id);
