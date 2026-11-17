-- Traces (OPR-3): the installation's pseudonym key. Every identifier in a
-- span is HMAC-SHA256(key, identifier), truncated (telemetry.Pseudonym), so
-- that an export of the traces names no organization, agent or person, while
-- the operator, who can read this row, can correlate. The API and the worker
-- read the same key, so an identifier has one pseudonym across processes.
-- Two random UUIDs give 244 random bits. The key stays in the database and
-- its backups; it never goes into a trace, a log or the diagnostic export.
CREATE TABLE trace_pseudonym_key (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  key bytea NOT NULL CHECK (octet_length(key) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO trace_pseudonym_key(key)
  VALUES (decode(replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-',''),'hex'));
