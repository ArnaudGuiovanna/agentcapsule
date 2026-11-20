-- Corpora (ADR 023 §5.4, §5.5). A system image declares, at its approval,
-- what its capsule-init can do beyond the base guest: corpus.mount, it reads
-- etc/capsule/corpora.json, checks each corpus drive's UUID and mounts the
-- corpora under /corpus; it also exposes the builder's build drives. An
-- older capsule-init would ignore corpora.json and boot without them.
ALTER TABLE system_images ADD COLUMN features text[] NOT NULL DEFAULT '{}'
  CHECK (features <@ ARRAY['corpus.mount']::text[]);

-- The guest base a release's harness.yaml names. Only a harness of base
-- agentcapsule-guest/2 has the /corpus mount point. Releases imported before
-- this column, and releases approved locally, are of base 1.
ALTER TABLE harness_releases ADD COLUMN base text NOT NULL DEFAULT 'agentcapsule-guest/1'
  CHECK (base IN ('agentcapsule-guest/1','agentcapsule-guest/2'));
