-- Platform credentials are a distinct trust domain. Existing service/user
-- tokens retain their legacy permissions and cannot administer organizations.
CREATE TABLE platform_credentials (
  id text PRIMARY KEY CHECK (id <> ''),
  account text NOT NULL CHECK (length(btrim(account)) BETWEEN 1 AND 100),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
  scopes text[] NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE http_receipts DROP CONSTRAINT http_receipts_actor_kind_check;
ALTER TABLE http_receipts ADD CONSTRAINT http_receipts_actor_kind_check
  CHECK (actor_kind IN ('user','service','platform'));

-- Administrative metadata only. Identity registration does not authenticate
-- the registered user; this audit never contains tokens or conversation data.
CREATE TABLE organization_audit (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  actor_account text NOT NULL,
  credential_id text NOT NULL REFERENCES platform_credentials(id),
  action text NOT NULL CHECK (action IN ('organization.created','organization.disabled')),
  changed boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX organization_audit_tenant ON organization_audit(tenant_id,created_at,id);
