ALTER TABLE agents ADD COLUMN kind text NOT NULL DEFAULT 'agent' CHECK(kind IN ('agent','corpus_builder')),
 ADD COLUMN builder_principal text,
 ADD CHECK((kind='corpus_builder')=(builder_principal IS NOT NULL)),
 ADD CHECK(kind<>'corpus_builder' OR (tenant_id IS NOT NULL AND NOT discoverable)),
 ADD FOREIGN KEY(tenant_id,builder_principal) REFERENCES principals(tenant_id,id);
CREATE UNIQUE INDEX one_corpus_builder_per_tenant ON agents(tenant_id) WHERE kind='corpus_builder';
CREATE UNIQUE INDEX one_agent_per_builder_principal ON agents(builder_principal) WHERE builder_principal IS NOT NULL;
ALTER TABLE corpus_builds ADD FOREIGN KEY(tenant_id,builder_agent_id) REFERENCES agents(tenant_id,id),
 ADD FOREIGN KEY(invocation_id) REFERENCES platform_operations(id),
 ADD COLUMN builder_digest text CHECK(builder_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE corpus_builds ADD COLUMN phase_started_at timestamptz NOT NULL DEFAULT clock_timestamp();
