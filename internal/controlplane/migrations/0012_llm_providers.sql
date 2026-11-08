-- LLM gateway control data (LLM-01). Provider credentials are stored only as
-- AES-GCM ciphertext under a key derived from the installation key, bound to the
-- tenant, provider and key generation. They never reach a VM, a volume archive,
-- an API response or a log. A model alias is the tenant's model policy: an agent
-- can only reach an upstream model that an active alias names.
CREATE TABLE llm_providers (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
  kind text NOT NULL CHECK (kind IN ('openai_compatible','anthropic')),
  base_url text NOT NULL CHECK (length(base_url) BETWEEN 8 AND 300),
  secret_ciphertext bytea NOT NULL,
  secret_generation bigint NOT NULL DEFAULT 1 CHECK (secret_generation > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  rotated_at timestamptz,
  disabled_at timestamptz,
  CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);

CREATE TABLE llm_model_aliases (
  tenant_id text NOT NULL,
  alias text NOT NULL CHECK (length(btrim(alias)) BETWEEN 1 AND 100),
  provider_id text NOT NULL,
  upstream_model text NOT NULL CHECK (length(btrim(upstream_model)) BETWEEN 1 AND 200),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  disabled_at timestamptz,
  CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, alias),
  FOREIGN KEY (tenant_id,provider_id) REFERENCES llm_providers(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);

CREATE TABLE llm_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_principal_id text NOT NULL,
  provider_id text NOT NULL,
  alias text,
  action text NOT NULL CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action LIKE 'alias.%') = (alias IS NOT NULL)),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,provider_id) REFERENCES llm_providers(tenant_id,id)
);
CREATE INDEX llm_audit_tenant ON llm_audit(tenant_id,created_at,id);
