-- Only trusted operator changes create issuer anchors. Authentication is read
-- only and cannot install a trust or manufacture a principal/membership.
CREATE TABLE delegation_issuers (
  tenant_id text NOT NULL REFERENCES organizations(id),
  issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 1024),
  PRIMARY KEY (tenant_id,issuer)
);
CREATE TABLE delegation_trusts (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  audience text NOT NULL CHECK (octet_length(audience) BETWEEN 1 AND 1024),
  fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
  status text NOT NULL CHECK (status IN ('active','revoked')),
  minimum_iat timestamptz NOT NULL,
  generation bigint NOT NULL CHECK (generation>0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,issuer,audience),
  FOREIGN KEY (tenant_id,issuer) REFERENCES delegation_issuers(tenant_id,issuer)
);
-- Permanent across trust rotations and audiences. Do not recycle token IDs or
-- delete tombstones when replacing a verifier/configuration.
CREATE TABLE delegation_revocations (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  token_id text NOT NULL CHECK (octet_length(token_id) BETWEEN 1 AND 1024),
  revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,issuer,token_id),
  FOREIGN KEY (tenant_id,issuer) REFERENCES delegation_issuers(tenant_id,issuer)
);
-- Operator-only receipts contain public configuration metadata, never a JWT.
CREATE TABLE delegation_admin_receipts (
  operation_id text PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 200),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE delegation_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES organizations(id),
  issuer text NOT NULL,
  audience text NOT NULL,
  token_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('install','rotate','revoke-trust','revoke-token')),
  actor text NOT NULL,
  operation_id text NOT NULL UNIQUE REFERENCES delegation_admin_receipts(operation_id),
  changed boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
