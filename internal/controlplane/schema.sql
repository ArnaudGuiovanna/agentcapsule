-- Control-plane metadata only: private message bodies belong in encrypted transit storage.
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Personal tokens never inherit service privileges from the user's role.
-- Only hashes are stored here; replayable issuance responses are encrypted.
CREATE TABLE IF NOT EXISTS api_tokens (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('user','service')),
  user_id text REFERENCES users(id),
  service_account text,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
  scopes text[] NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((kind='user' AND user_id IS NOT NULL AND service_account IS NULL)
      OR (kind='service' AND user_id IS NULL AND service_account IS NOT NULL AND service_account<>''))
);
CREATE TABLE IF NOT EXISTS http_receipts (
  actor_kind text NOT NULL CHECK (actor_kind IN ('user','service')),
  actor_id text NOT NULL,
  method text NOT NULL,
  route text NOT NULL,
  key text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
  response_status integer NOT NULL CHECK (response_status BETWEEN 200 AND 299),
  response_ciphertext bytea NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
  PRIMARY KEY (actor_kind,actor_id,method,route,key)
);
CREATE TABLE IF NOT EXISTS api_receipt_key (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32)
);
CREATE TABLE IF NOT EXISTS agents (
  id text PRIMARY KEY,
  owner_user_id text NOT NULL UNIQUE,
  phase text NOT NULL DEFAULT 'LIVE' CHECK (phase IN ('LIVE','QUIESCING','DELETING','DELETED')),
  discoverable boolean NOT NULL DEFAULT false,
  inbound_mode text NOT NULL DEFAULT 'manual' CHECK (inbound_mode IN ('manual','auto')),
  next_seq bigint NOT NULL DEFAULT 0 CHECK (next_seq >= 0)
);
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_phase_check;
ALTER TABLE agents ADD CONSTRAINT agents_phase_check
  CHECK (phase IN ('PROVISIONING','LIVE','QUIESCING','DELETING','DELETED'));
CREATE TABLE IF NOT EXISTS harness_releases (
  id text PRIMARY KEY,
  name text NOT NULL,
  version text NOT NULL,
  artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  source text NOT NULL CHECK (source IN ('local-approved','oci')),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (name,version)
);
-- One provisioned host per volume. Moving a volume to another host requires a
-- separate physical fencing/provisioning protocol; lease expiry is insufficient.
CREATE TABLE IF NOT EXISTS agent_placements (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  host_id text NOT NULL CHECK (host_id <> ''),
  generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  state text NOT NULL DEFAULT 'STOPPED' CHECK (state IN ('STOPPED','STARTING','RUNNING','STOPPING')),
  worker_id text NOT NULL DEFAULT '',
  lease_until timestamptz,
  vm_id text NOT NULL DEFAULT '',
  unclean_stop boolean NOT NULL DEFAULT false,
  CHECK ((state='STARTING') = (lease_until IS NOT NULL)),
  CHECK (state <> 'STARTING' OR worker_id <> ''),
  CHECK (state <> 'RUNNING' OR vm_id <> ''),
  CHECK (state <> 'STOPPED' OR (vm_id='' AND worker_id='')),
  CHECK (state='STOPPED' OR generation > 0)
);
ALTER TABLE agent_placements ADD COLUMN IF NOT EXISTS fence_only boolean NOT NULL DEFAULT false;
-- A replacement owed to an ordinary LIVE boot, committed with STOPPING. It
-- survives worker/VM/database crashes until a physically confirmed successor
-- is observed, or an explicit stop/deletion cancels it.
CREATE TABLE IF NOT EXISTS placement_renewals (
  agent_id text PRIMARY KEY REFERENCES agent_placements(agent_id),
  host_id text NOT NULL CHECK (host_id <> ''),
  from_generation bigint NOT NULL CHECK (from_generation > 0),
  from_vm_id text NOT NULL CHECK (from_vm_id <> ''),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS mandates (
  id text PRIMARY KEY,
  agent_id text NOT NULL REFERENCES agents(id),
  origin_event_id text NOT NULL,
  max_requests integer NOT NULL CHECK (max_requests > 0),
  remaining integer NOT NULL CHECK (remaining >= 0 AND remaining <= max_requests),
  expires_at timestamptz NOT NULL,
  valid boolean NOT NULL DEFAULT true,
  UNIQUE (id, agent_id)
);
CREATE TABLE IF NOT EXISTS agent_requests (
  id text PRIMARY KEY,
  sender_agent_id text NOT NULL REFERENCES agents(id),
  recipient_agent_id text NOT NULL REFERENCES agents(id),
  mandate_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING','REPLIED','DECLINED','EXPIRED','CANCELED','FAILED')),
  via_auto boolean NOT NULL,
  accepted boolean NOT NULL DEFAULT false,
  delivered boolean NOT NULL DEFAULT false,
  payload_ref text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  decided_at timestamptz,
  decided_by text,
  CHECK (sender_agent_id <> recipient_agent_id),
  CHECK (NOT delivered OR via_auto OR accepted),
  FOREIGN KEY (mandate_id, sender_agent_id) REFERENCES mandates(id, agent_id)
);
ALTER TABLE agent_requests ADD COLUMN IF NOT EXISTS payload_hash bytea CHECK (octet_length(payload_hash)=32);
ALTER TABLE agent_requests ADD COLUMN IF NOT EXISTS reply_ref text NOT NULL DEFAULT '';
ALTER TABLE agent_requests ADD COLUMN IF NOT EXISTS reply_hash bytea CHECK (octet_length(reply_hash)=32);
ALTER TABLE agent_requests ADD COLUMN IF NOT EXISTS sender_notified boolean NOT NULL DEFAULT false;
ALTER TABLE agent_requests ADD COLUMN IF NOT EXISTS recipient_visible_at_submit boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS mandate_origin_once ON mandates(agent_id,origin_event_id);
CREATE TABLE IF NOT EXISTS idempotency_keys (
  actor text NOT NULL,
  operation text NOT NULL,
  key text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response_ref text NOT NULL REFERENCES agent_requests(id) DEFERRABLE INITIALLY DEFERRED,
  response_state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (actor, operation, key)
);
CREATE TABLE IF NOT EXISTS agent_mailboxes (
  id text PRIMARY KEY,
  dest_agent_id text NOT NULL REFERENCES agents(id),
  seq bigint NOT NULL CHECK (seq > 0),
  kind text NOT NULL CHECK (kind IN ('request','reply','status')),
  ref_id text NOT NULL REFERENCES agent_requests(id),
  delivery_state text NOT NULL DEFAULT 'PENDING' CHECK (delivery_state IN ('PENDING','DELIVERED','DEAD','CANCELED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at timestamptz NOT NULL,
  UNIQUE (dest_agent_id, seq),
  UNIQUE (kind, ref_id)
);
-- Upgrade installations created before status-only cancellation notifications.
-- Migrate holds the migration lock and applies this change transactionally.
ALTER TABLE agent_mailboxes DROP CONSTRAINT IF EXISTS agent_mailboxes_kind_check;
ALTER TABLE agent_mailboxes ADD CONSTRAINT agent_mailboxes_kind_check
  CHECK (kind IN ('request','reply','status','instruction'));
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS attempt_limit integer NOT NULL DEFAULT 3 CHECK (attempt_limit > 0);
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS lease_token text NOT NULL DEFAULT '';
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS lease_until timestamptz;
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS closing boolean NOT NULL DEFAULT false;
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS may_have_reached boolean NOT NULL DEFAULT false;
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS dispatch_authorized boolean NOT NULL DEFAULT false;
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS status_reason text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS outbox (
  id text PRIMARY KEY,
  mailbox_id text NOT NULL UNIQUE REFERENCES agent_mailboxes(id),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
-- Scheduler tickets are allocated transactionally per host. Claims move work to
-- the tail; lease expiry coordinates retries, never proves a VM/RPC absent.
CREATE TABLE IF NOT EXISTS worker_hosts (
  host_id text PRIMARY KEY CHECK (host_id <> ''),
  next_ticket bigint NOT NULL DEFAULT 0 CHECK (next_ticket >= 0)
);
ALTER TABLE worker_hosts ADD COLUMN IF NOT EXISTS storage_limit_mib bigint NOT NULL DEFAULT 0 CHECK (storage_limit_mib>=0);
CREATE TABLE IF NOT EXISTS agent_specs (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  name text NOT NULL,
  release_id text NOT NULL REFERENCES harness_releases(id),
  host_id text NOT NULL REFERENCES worker_hosts(host_id),
  vcpus integer NOT NULL CHECK (vcpus BETWEEN 1 AND 8),
  memory_mib integer NOT NULL CHECK (memory_mib BETWEEN 128 AND 8192),
  volume_mib integer NOT NULL CHECK (volume_mib BETWEEN 64 AND 32768),
  auto_start boolean NOT NULL,
  next_operation_seq bigint NOT NULL DEFAULT 1 CHECK (next_operation_seq>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS platform_operations (
  id text PRIMARY KEY,
  owner_user_id text NOT NULL REFERENCES users(id),
  agent_id text NOT NULL REFERENCES agents(id),
  host_id text NOT NULL REFERENCES worker_hosts(host_id),
  seq bigint NOT NULL CHECK (seq>0),
  kind text NOT NULL CHECK (kind IN ('provision','wake','sleep','delete','instruction')),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELED')),
  error_code text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  UNIQUE (agent_id,seq)
);
ALTER TABLE platform_operations ADD COLUMN IF NOT EXISTS unclean_stop boolean;
-- Private bodies live only in this encrypted transit area, never in operation,
-- mailbox or HTTP receipt bodies. Key material is supplied outside PostgreSQL.
CREATE TABLE IF NOT EXISTS transit_keys (
  id text PRIMARY KEY,
  key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32)
);
CREATE TABLE IF NOT EXISTS transit_configuration (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  active_key_id text NOT NULL REFERENCES transit_keys(id)
);
CREATE TABLE IF NOT EXISTS transit_payloads (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('instruction','instruction_result','request','reply','owner_message')),
  ref_id text NOT NULL,
  key_id text NOT NULL REFERENCES transit_keys(id),
  content_hash bytea NOT NULL CHECK (octet_length(content_hash)=32),
  ciphertext bytea,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  purge_after timestamptz,
  purged_at timestamptz,
  CHECK ((ciphertext IS NULL) = (purged_at IS NOT NULL)),
  CHECK (ciphertext IS NULL OR octet_length(ciphertext) BETWEEN 28 AND 524316),
  CHECK ((delivered_at IS NULL) = (purge_after IS NULL)),
  UNIQUE (kind,ref_id)
);
CREATE TABLE IF NOT EXISTS transit_parties (
  payload_id text NOT NULL REFERENCES transit_payloads(id),
  agent_id text NOT NULL REFERENCES agents(id),
  owner_user_id text NOT NULL,
  PRIMARY KEY (payload_id,agent_id)
);
CREATE INDEX IF NOT EXISTS transit_party_agent ON transit_parties(agent_id,payload_id);
CREATE TABLE IF NOT EXISTS owner_instructions (
  operation_id text PRIMARY KEY REFERENCES platform_operations(id),
  input_payload_id text NOT NULL UNIQUE REFERENCES transit_payloads(id),
  result_payload_id text UNIQUE REFERENCES transit_payloads(id),
  mandate_id text UNIQUE REFERENCES mandates(id),
  max_agent_requests integer NOT NULL DEFAULT 3 CHECK (max_agent_requests BETWEEN 1 AND 3)
);
ALTER TABLE agent_mailboxes ALTER COLUMN ref_id DROP NOT NULL;
ALTER TABLE agent_mailboxes ADD COLUMN IF NOT EXISTS instruction_id text UNIQUE REFERENCES owner_instructions(operation_id);
ALTER TABLE agent_mailboxes DROP CONSTRAINT IF EXISTS agent_mailboxes_kind_check;
ALTER TABLE agent_mailboxes ADD CONSTRAINT agent_mailboxes_kind_check CHECK (kind IN ('request','reply','status','instruction'));
ALTER TABLE agent_mailboxes DROP CONSTRAINT IF EXISTS agent_mailboxes_reference_check;
ALTER TABLE agent_mailboxes ADD CONSTRAINT agent_mailboxes_reference_check CHECK (
  (kind='instruction' AND instruction_id IS NOT NULL AND ref_id IS NULL)
  OR (kind<>'instruction' AND instruction_id IS NULL AND ref_id IS NOT NULL));
CREATE TABLE IF NOT EXISTS worker_jobs (
  host_id text NOT NULL REFERENCES worker_hosts(host_id),
  kind text NOT NULL CHECK (kind IN ('delivery','closure','deletion','expiration','provision','lifecycle')),
  object_id text NOT NULL CHECK (object_id <> ''),
  agent_id text NOT NULL REFERENCES agents(id),
  ticket bigint NOT NULL CHECK (ticket > 0),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token text NOT NULL DEFAULT '',
  lease_until timestamptz,
  failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 30),
  PRIMARY KEY (host_id,kind,object_id),
  UNIQUE (host_id,ticket),
  CHECK ((lease_token='') = (lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS pending_mailbox_order ON agent_mailboxes(dest_agent_id,seq) WHERE delivery_state='PENDING';
ALTER TABLE worker_jobs DROP CONSTRAINT IF EXISTS worker_jobs_kind_check;
ALTER TABLE worker_jobs ADD CONSTRAINT worker_jobs_kind_check
  CHECK (kind IN ('delivery','closure','deletion','expiration','provision','lifecycle'));
CREATE TABLE IF NOT EXISTS owner_messages (
  id text PRIMARY KEY,
  agent_id text NOT NULL REFERENCES agents(id),
  owner_user_id text NOT NULL,
  request_id text REFERENCES agent_requests(id),
  payload_id text NOT NULL UNIQUE REFERENCES transit_payloads(id),
  idempotency_key text NOT NULL,
  body_hash bytea NOT NULL CHECK (octet_length(body_hash)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(agent_id,idempotency_key)
);
CREATE TABLE IF NOT EXISTS inbox_items (
  id text PRIMARY KEY,
  user_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('request_pending','request_update')),
  ref_id text NOT NULL REFERENCES agent_requests(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE inbox_items ALTER COLUMN ref_id DROP NOT NULL;
ALTER TABLE inbox_items ADD COLUMN IF NOT EXISTS owner_message_id text UNIQUE REFERENCES owner_messages(id);
ALTER TABLE inbox_items DROP CONSTRAINT IF EXISTS inbox_items_kind_check;
ALTER TABLE inbox_items ADD CONSTRAINT inbox_items_kind_check CHECK (kind IN ('request_pending','request_update','agent_message'));
ALTER TABLE inbox_items DROP CONSTRAINT IF EXISTS inbox_items_reference_check;
ALTER TABLE inbox_items ADD CONSTRAINT inbox_items_reference_check CHECK (
  (kind='agent_message' AND owner_message_id IS NOT NULL AND ref_id IS NULL)
  OR (kind<>'agent_message' AND ref_id IS NOT NULL AND owner_message_id IS NULL));
CREATE TABLE IF NOT EXISTS deletion_operations (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  requested_by text NOT NULL,
  phase text NOT NULL DEFAULT 'FENCING' CHECK (phase IN ('FENCING','TOMBSTONED')),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE deletion_operations ADD COLUMN IF NOT EXISTS operation_id text UNIQUE REFERENCES platform_operations(id);
CREATE TABLE IF NOT EXISTS deletion_targets (
  agent_id text NOT NULL REFERENCES deletion_operations(agent_id),
  store_agent_id text NOT NULL REFERENCES agents(id),
  acknowledged boolean NOT NULL DEFAULT false,
  PRIMARY KEY (agent_id, store_agent_id)
);
CREATE TABLE IF NOT EXISTS request_closures (
  request_id text PRIMARY KEY REFERENCES agent_requests(id),
  final_state text NOT NULL CHECK (final_state IN ('EXPIRED','CANCELED','FAILED')),
  reason text NOT NULL,
  phase text NOT NULL DEFAULT 'FENCING' CHECK (phase IN ('FENCING','COMMITTED')),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS request_closure_targets (
  request_id text NOT NULL REFERENCES request_closures(request_id),
  store_agent_id text NOT NULL REFERENCES agents(id),
  acknowledged boolean NOT NULL DEFAULT false,
  PRIMARY KEY (request_id, store_agent_id)
);
-- New stores must catch up before gaining ordinary authority. This catalogue
-- is local to the control database; D5 still requires an independent authority
-- for restoration of that database itself.
CREATE TABLE IF NOT EXISTS revocation_catalogue (
  subject text PRIMARY KEY CHECK (subject ~ '^(agent|request|event)/.+$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO revocation_catalogue(subject)
  SELECT 'agent/'||agent_id FROM deletion_operations
  UNION SELECT 'request/'||request_id FROM request_closures
  UNION SELECT 'event/'||id FROM agent_mailboxes WHERE closing
ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION preserve_revocation_catalogue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'revocation catalogue is permanent' USING ERRCODE='23514';
END
$$;
DROP TRIGGER IF EXISTS revocation_catalogue_guard ON revocation_catalogue;
CREATE TRIGGER revocation_catalogue_guard BEFORE UPDATE OR DELETE ON revocation_catalogue
FOR EACH ROW EXECUTE FUNCTION preserve_revocation_catalogue();
CREATE TABLE IF NOT EXISTS store_enrollments (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  operation_id text NOT NULL UNIQUE REFERENCES platform_operations(id),
  volume_id text NOT NULL UNIQUE CHECK (volume_id ~ '^vol_[0-9a-f]{32}$'),
  incarnation bigint NOT NULL DEFAULT 1 CHECK (incarnation>0),
  stage text NOT NULL DEFAULT 'INSTALLING' CHECK (stage IN ('INSTALLING','FENCING','READY')),
  volume_device text CHECK (volume_device ~ '^[0-9a-f]{16}$'),
  volume_inode text CHECK (volume_inode ~ '^[0-9a-f]{16}$'),
  CHECK ((stage='INSTALLING') = (volume_device IS NULL AND volume_inode IS NULL)),
  CHECK (stage='INSTALLING' OR (volume_device IS NOT NULL AND volume_inode IS NOT NULL)),
  UNIQUE (agent_id,volume_id)
);
ALTER TABLE store_enrollments ADD COLUMN IF NOT EXISTS incarnation bigint NOT NULL DEFAULT 1 CHECK (incarnation>0);
-- Upgrade reservations created by the previous catalogue-only implementation.
-- That implementation could not create or register a physical volume. Never
-- invent a new identity for a reservation which already has a placement.
INSERT INTO store_enrollments(agent_id,operation_id,volume_id)
  SELECT a.id,o.id,'vol_'||replace(gen_random_uuid()::text,'-','')
  FROM agents a JOIN platform_operations o ON o.agent_id=a.id
  WHERE a.phase='PROVISIONING' AND o.kind='provision' AND o.status='PENDING'
    AND NOT EXISTS(SELECT 1 FROM agent_placements p WHERE p.agent_id=a.id)
    AND NOT EXISTS(SELECT 1 FROM store_enrollments e WHERE e.agent_id=a.id)
ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS store_enrollment_receipts (
  agent_id text NOT NULL,
  volume_id text NOT NULL,
  subject text NOT NULL REFERENCES revocation_catalogue(subject),
  boot_generation bigint NOT NULL CHECK (boot_generation>0),
  boot_vm_id text NOT NULL CHECK (boot_vm_id<>''),
  PRIMARY KEY (agent_id,volume_id,subject),
  FOREIGN KEY (agent_id,volume_id) REFERENCES store_enrollments(agent_id,volume_id)
);
ALTER TABLE store_enrollment_receipts ADD COLUMN IF NOT EXISTS incarnation bigint NOT NULL DEFAULT 1 CHECK (incarnation>0);
-- The container's LUKS header is not proof of an initialized private filesystem.
-- This receipt follows authenticated guest readiness for the assigned volume.
CREATE TABLE IF NOT EXISTS store_initializations (
  agent_id text PRIMARY KEY,
  volume_id text NOT NULL,
  boot_generation bigint NOT NULL CHECK (boot_generation>0),
  boot_vm_id text NOT NULL CHECK (boot_vm_id<>''),
  initialized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (agent_id,volume_id) REFERENCES store_enrollments(agent_id,volume_id)
);
ALTER TABLE store_initializations ADD COLUMN IF NOT EXISTS incarnation bigint NOT NULL DEFAULT 1 CHECK (incarnation>0);
CREATE OR REPLACE FUNCTION preserve_store_initialization() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'initialized store cannot be reset through provisioning' USING ERRCODE='23514';
END
$$;
DROP TRIGGER IF EXISTS store_initialization_guard ON store_initializations;
CREATE TRIGGER store_initialization_guard BEFORE UPDATE OR DELETE ON store_initializations
FOR EACH ROW EXECUTE FUNCTION preserve_store_initialization();
CREATE OR REPLACE FUNCTION preserve_enrollment_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.agent_id,NEW.operation_id,NEW.volume_id,NEW.incarnation) IS DISTINCT FROM
     (OLD.agent_id,OLD.operation_id,OLD.volume_id,OLD.incarnation) OR
     (OLD.stage<>'INSTALLING' AND (NEW.volume_device,NEW.volume_inode) IS DISTINCT FROM
       (OLD.volume_device,OLD.volume_inode)) OR
     (OLD.stage='READY' AND NEW.stage<>'READY') OR
     (OLD.stage='FENCING' AND NEW.stage='INSTALLING') THEN
    RAISE EXCEPTION 'enrollment identity cannot be replaced or reset' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS enrollment_identity_guard ON store_enrollments;
CREATE TRIGGER enrollment_identity_guard BEFORE UPDATE ON store_enrollments
FOR EACH ROW EXECUTE FUNCTION preserve_enrollment_identity();
-- Execution retirement only. Data/key destruction is a separate obligation.
CREATE TABLE IF NOT EXISTS store_seals (
  agent_id text PRIMARY KEY REFERENCES agent_placements(agent_id),
  host_id text NOT NULL CHECK (host_id<>''),
  generation bigint NOT NULL CHECK (generation>=0),
  seal_id text NOT NULL CHECK (seal_id ~ '^[0-9a-f]{32}$'),
  volume_device text NOT NULL CHECK (volume_device ~ '^[0-9a-f]{16}$'),
  volume_inode text NOT NULL CHECK (volume_inode ~ '^[0-9a-f]{16}$'),
  sealed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION preserve_store_seal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'store seal is permanent' USING ERRCODE='23514';
END
$$;
DROP TRIGGER IF EXISTS store_seal_guard ON store_seals;
CREATE TRIGGER store_seal_guard BEFORE UPDATE OR DELETE ON store_seals
FOR EACH ROW EXECUTE FUNCTION preserve_store_seal();
CREATE TABLE IF NOT EXISTS store_removals (
  agent_id text PRIMARY KEY REFERENCES store_seals(agent_id),
  volume_id text NOT NULL UNIQUE,
  seal_id text NOT NULL CHECK (seal_id ~ '^[0-9a-f]{32}$'),
  removed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS store_removal_guard ON store_removals;
CREATE TRIGGER store_removal_guard BEFORE UPDATE OR DELETE ON store_removals
FOR EACH ROW EXECUTE FUNCTION preserve_store_seal();
CREATE OR REPLACE FUNCTION preserve_sealed_placement() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM store_seals s WHERE s.agent_id=NEW.agent_id AND
      (NEW.state<>'STOPPED' OR NEW.host_id<>s.host_id OR NEW.generation<>s.generation)) THEN
    RAISE EXCEPTION 'sealed store cannot be placed again' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS sealed_placement_guard ON agent_placements;
CREATE TRIGGER sealed_placement_guard BEFORE UPDATE ON agent_placements
FOR EACH ROW EXECUTE FUNCTION preserve_sealed_placement();
CREATE OR REPLACE FUNCTION preserve_sealed_agent() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF OLD.phase='DELETED' AND NEW.phase<>'DELETED' THEN
    RAISE EXCEPTION 'deleted agent is permanent' USING ERRCODE='23514';
  END IF;
  IF NEW.phase IN ('PROVISIONING','LIVE','QUIESCING') AND EXISTS(SELECT 1 FROM store_seals WHERE agent_id=NEW.id) THEN
    RAISE EXCEPTION 'sealed agent cannot be reactivated' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS sealed_agent_guard ON agents;
CREATE TRIGGER sealed_agent_guard BEFORE UPDATE ON agents
FOR EACH ROW EXECUTE FUNCTION preserve_sealed_agent();
CREATE OR REPLACE FUNCTION preserve_request_identity_and_terminal_state() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.sender_agent_id, NEW.recipient_agent_id, NEW.mandate_id, NEW.payload_ref, NEW.payload_hash) IS DISTINCT FROM
     (OLD.sender_agent_id, OLD.recipient_agent_id, OLD.mandate_id, OLD.payload_ref, OLD.payload_hash) THEN
    RAISE EXCEPTION 'request identity is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.state IN ('REPLIED','DECLINED','EXPIRED','CANCELED','FAILED') AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'terminal request state is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.state IN ('REPLIED','DECLINED','EXPIRED','CANCELED','FAILED') AND
     (NEW.reply_ref, NEW.reply_hash) IS DISTINCT FROM (OLD.reply_ref, OLD.reply_hash) THEN
    RAISE EXCEPTION 'terminal reply is immutable' USING ERRCODE='23514';
  END IF;
  IF (NEW.state='REPLIED') <> (NEW.reply_ref<>'' AND NEW.reply_hash IS NOT NULL) THEN
    RAISE EXCEPTION 'reply state and content must commit together' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS request_state_guard ON agent_requests;
CREATE TRIGGER request_state_guard BEFORE UPDATE ON agent_requests
FOR EACH ROW EXECUTE FUNCTION preserve_request_identity_and_terminal_state();
-- Stable owner receipts must never be rebound to another owner, payload, key
-- or request. Content erasure happens only in the encrypted transit row.
CREATE OR REPLACE FUNCTION preserve_owner_message() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'owner message identity and receipt are permanent' USING ERRCODE='23514';
END
$$;
DROP TRIGGER IF EXISTS owner_message_guard ON owner_messages;
CREATE TRIGGER owner_message_guard BEFORE UPDATE OR DELETE ON owner_messages
FOR EACH ROW EXECUTE FUNCTION preserve_owner_message();
