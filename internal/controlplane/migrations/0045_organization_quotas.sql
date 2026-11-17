-- Organization quotas (TEN-007, ADR 021): how many agents an organization may
-- hold, how much volume storage they reserve, how many of their VMs may run
-- at once and the vCPUs and RAM those VMs reserve. The platform operator sets
-- them. A NULL column has no limit, and an organization without a row has
-- none: an existing installation keeps working unchanged.
--
-- Creating an agent checks the agents, the storage and that the agent alone
-- fits the vCPU and RAM quotas, before any reservation. Booting an agent for
-- work checks the active VMs, vCPUs and RAM, in the transaction that reserves
-- the boot (agent_placements). Both serialize per organization on an
-- advisory lock, so concurrent creations and boots never exceed a quota.
CREATE TABLE organization_quotas (
  tenant_id text PRIMARY KEY REFERENCES organizations(id),
  max_agents integer CHECK (max_agents BETWEEN 1 AND 100000),
  max_active_vms integer CHECK (max_active_vms BETWEEN 1 AND 100000),
  max_vcpus integer CHECK (max_vcpus BETWEEN 1 AND 1000000),
  max_memory_mib bigint CHECK (max_memory_mib BETWEEN 128 AND 1073741824),
  max_storage_mib bigint CHECK (max_storage_mib BETWEEN 64 AND 1099511627776),
  updated_by text NOT NULL CHECK (updated_by <> ''),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Why an agent waits in its host's capacity queue (ADR 017): for a VM slot of
-- the host ('capacity'), or for room under its organization's quota
-- ('organization_quota'). Each decision sets it again. A waiter for its
-- organization's quota does not hold back other organizations' work.
ALTER TABLE capacity_waits ADD COLUMN reason text NOT NULL DEFAULT 'capacity'
  CHECK (reason IN ('capacity','organization_quota'));

-- A change of quotas joins the platform's audit of the organization, which
-- the organization reads in its trail.
ALTER TABLE organization_audit DROP CONSTRAINT organization_audit_action_check;
ALTER TABLE organization_audit ADD CONSTRAINT organization_audit_action_check
  CHECK (action IN ('organization.created','organization.disabled','organization.quotas_set'));
