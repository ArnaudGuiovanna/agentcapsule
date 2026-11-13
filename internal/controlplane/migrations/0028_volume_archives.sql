-- Volume archives (REC-02, ADR 004): the maintenance worker archives each
-- agent's encrypted volume into the host's local archive root, once a day.
-- One row per capture that may have published an archive. It is metadata
-- only: never content, never a key. The row is written before the capture
-- starts, so an archive published just before a crash is always known:
-- captured_at stays NULL until the archive is known to be published, and the
-- next capture of the agent settles such a row from the archive root.
-- removed_at is set when local retention deletes the archive.
CREATE TABLE volume_archives (
  archive_id text PRIMARY KEY CHECK (archive_id ~ '^arc_[0-9a-f]{32}$'),
  agent_id text NOT NULL,
  host_id text NOT NULL CHECK (host_id <> ''),
  volume_id text NOT NULL,
  incarnation bigint NOT NULL CHECK (incarnation > 0),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  captured_at timestamptz,
  size bigint CHECK (size > 0),
  removed_at timestamptz,
  CHECK ((captured_at IS NULL) = (size IS NULL)),
  CHECK (removed_at IS NULL OR captured_at IS NOT NULL),
  FOREIGN KEY (agent_id, volume_id) REFERENCES store_enrollments(agent_id, volume_id)
);
CREATE INDEX volume_archives_agent ON volume_archives(agent_id, host_id, captured_at);
