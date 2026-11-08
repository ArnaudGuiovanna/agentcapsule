-- Compatibility is observed for one authenticated boot. Existing physical
-- RUNNING placements receive no retroactive application-readiness proof.
CREATE TABLE placement_control_contracts (
  agent_id text PRIMARY KEY REFERENCES agent_placements(agent_id),
  host_id text NOT NULL CHECK (host_id <> ''),
  generation bigint NOT NULL CHECK (generation > 0),
  vm_id text NOT NULL CHECK (vm_id <> ''),
  incarnation bigint NOT NULL CHECK (incarnation > 0),
  protocol text NOT NULL CHECK (protocol = 'capsule.v1'),
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
