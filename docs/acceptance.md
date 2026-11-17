# Acceptance of the MVP

This page maps the MVP to the tests that prove it (VAL-02):
- each P0 requirement of [product.md §4](product.md#4-mvp-p0-requirements), against its acceptance criterion;
- the MVP outcome of [§1](product.md#1-problem-and-vision), as one ordered scenario;
- the deployment and operations promises of [§2](product.md#2-users-and-deployment-model) and [§3](product.md#operations-and-recovery).

A row is **met** only if a test checks the acceptance criterion itself, not
just the feature. `scripts/check-acceptance.py`, run by the hygiene check,
fails when a requirement of §4 has no row, when a met row cites no test, or
when a cited test or file no longer exists.

State on 2026-11-16: `mvp-integration` with the install from scratch, then
the day's merges:
- JSON content, download links and capabilities (ADR 016);
- the capacity queue, `QUEUED` and the replay of dead letters (ADR 017);
- operations: storage pressure, diagnostics, guarded commands, audit
  retention and the load test (ADR 014);
- the model providers' egress check, which no row of §4 names (OPS-01 and
  LLM-02 in the roadmap);
- key destruction checking the seal (ADR 006 wave 3);
- the API on the authority service (ADR 006 wave 4);
- the KVM tests the rows lacked (RUN-002, RUN-008, EVT-002, EVT-010,
  A2A-005, A2A-010, OPR-10, OPR-18), never run yet, the runtime disk at
  every start of the worker (DEP-3) and the refill of the harness cache
  (OPR-10).
- the API conventions checked route by route, and the curl examples run by
  a test (EXT-008).
- the security, audit and durability tests of the acceptance (refused
  attempts in the organization's trail, ADR 014 §10): TEN-009, REG-008,
  EVT-001, LLM-003, LLM-005, LLM-006 and LLM-008 are met.

Work still landing will change rows: the restore onto another host (OUT-7,
OPR-12).

Update the row with the change that proves it.

## How to read it

| Status | Meaning |
|---|---|
| met | A test checks the acceptance criterion itself, and its last run passed. |
| partial | Tests check part of the criterion. The last column says what is not proven. |
| not met | No test checks the criterion. The feature may exist. |
| needs KVM | Only a run on KVM or on a production host can prove it, and none has passed yet. |

Each test is followed by its kind:

| Kind | Where it runs |
|---|---|
| unit | `go test`, no database; in CI |
| PG | real PostgreSQL, through `scripts/verify-postgres.py`; in CI |
| KVM | jailed Firecracker as root, through `scripts/verify-product-guest.py` or `verify-runtime.py`; never in CI. The date is its last passing run |
| interop | the private Directory and SLIM node, through `scripts/verify-interop.py --services`; in CI |
| script | a `scripts/verify-*.py` campaign; in CI unless said |

**KVM dates.** The product tests last passed on 2026-11-15, with guest v20.
The control and runtime tests last passed on 2026-11-09. The code changed
since: drive rate limiters, a network namespace per VMM and the restart
budget (ADR 012); delivery closure (ADR 007); the worker on the authority
service and the seal check (ADR 006 waves 2 and 3); JSON content,
capabilities and the bounded guest `/tmp` (ADR 016); the capacity queue
(ADR 017); the organization quotas, whose stops and waits go through the
capacity queue (ADR 021). A met row that rests on a KVM test holds for the
code of that run. The next KVM run with the integrated guest must confirm it
([below](#kvm-runs-the-mvp-still-needs)).

## Summary

Of the 65 requirements of §4: 55 met, 3 partial, 0 not met, 7 needs KVM.

| Part | Met | Partial | Not met | Needs KVM |
|---|---|---|---|---|
| Organizations, identity and authorization | 9 | 0 | 0 | 0 |
| Isolation | 6 | 1 | 0 | 0 |
| Harness registry and supply chain | 8 | 2 | 0 | 0 |
| Capsules and runtime | 9 | 0 | 0 | 3 |
| Invocations and events | 8 | 0 | 0 | 2 |
| LLM gateway | 7 | 1 | 0 | 0 |
| Discovery and inter-agent communication | 10 | 0 | 0 | 2 |
| Content, capabilities and clients | 4 | 0 | 0 | 0 |
| API conventions | 8 | 1 | 0 | 0 |
| The MVP outcome as one scenario | 4 | 2 | 0 | 1 |
| Deployment and operations | 11 | 5 | 4 | 3 |
| **All rows** | **84** | **12** | **4** | **11** |

## Requirements

### Organizations, identity and authorization

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| TEN-001 | Platform operator or bootstrap only; audited | met | [`TestHTTPOrganizationsPlatformBoundaryAndReplay`](../internal/api/organizations_test.go) (PG): only the platform credential creates, reads, lists and disables organizations; [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): the organization routes answer 403 to every organization caller; [`TestOrganizationAuditFailureRollsBackCreationAndDisable`](../internal/controlplane/organizations_test.go) (PG): no change without its audit row; [`TestOperatorBootstrapFromEmptyDatabase`](../internal/api/bootstrap_test.go) (PG, real binaries) | — |
| TEN-002 | Out-of-tenant access refused, even with guessed IDs | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): another organization's owner, with every scope and the real IDs, gets 404 on every ID route; [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): cross-organization calls answer like an unknown ID; [`TestHTTPMembersTenantAndCredentialBoundaries`](../internal/api/members_test.go), [`TestHTTPTeamsTenantAndCredentialBoundaries`](../internal/api/teams_test.go) (PG) | — (proved route by route; no check that every table carries `tenant_id`) |
| TEN-003 | RBAC matrix tested per role and resource | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): every route against 13 kinds of caller, to the exact status; [`TestRBACMatrixCoversEveryRoute`](../internal/api/rbac_matrix_test.go), [`TestRBACMatrixIsDocumented`](../internal/api/rbac_matrix_test.go) (unit, CI); [`TestAdministrativeRoles`](../internal/authorization/policy_test.go) (unit): no role invokes or reads content | — |
| TEN-004 | Instant revocation; tokens stored hashed; creation logged | met | [`TestServiceTokenRevocationDisablingAndCascade`](../internal/controlplane/service_accounts_test.go) (PG): a revoked token is refused, also for a caller authenticated before; [`TestServiceAccountRolesAndTokenBounds`](../internal/controlplane/service_accounts_test.go) (PG): the stored hash is SHA-256 of the secret; [`TestHTTPServiceAccountsEndToEnd`](../internal/api/tenant_agents_test.go) (PG); [`TestAuditFeedIsCompletePagedAndMetadataOnly`](../internal/controlplane/audit_feed_test.go) (PG): creation and issue audited | — (expiry is enforced but untested) |
| TEN-005 | Unassigned members can neither invoke nor read | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): unassigned and former assignees get 404 on the agent, invoke, results and attachments; [`TestHTTPTenantInvocationIsGovernedByAssignments`](../internal/api/tenant_agents_test.go) (PG); [`TestTenantAgentsAssignmentsAndRevokedMemberKeepsAgent`](../internal/controlplane/tenant_agents_test.go) (PG) | — |
| TEN-006 | Revoked sessions and tokens make no new call | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): revoked members and tokens get 401 on every route, and every revoking route records its revocation with the authority service; [`TestHTTPMembersIdempotencyAndRevocation`](../internal/api/members_test.go) (PG): a token signed before the revocation is refused, replays included; [`TestMembersRevocationWaitsForAdmissionAndRefusesStaleReplay`](../internal/controlplane/members_test.go) (PG); [`TestGrantRevocationWaitsForReplica`](../internal/api/revocation_runs_test.go) (PG, real authority service): in degraded mode the revoked member's next call is refused at once, while the revocation stays `pending`; [`TestRevocationTriesAgainWithoutTheAuthorityService`](../internal/api/revocations_test.go) (PG): a revocation the authority service did not record changes nothing and answers 503 `authority_unavailable`; [`TestReconciliationReplaysRoot`](../internal/api/reconciliation_runs_test.go), [`TestTokenRevocationCoveredByBlanket`](../internal/api/reconciliation_runs_test.go) (PG, real authority service and its promotion): after a failover, a member revoked after the last WAL shipment, and a token revoked in degraded mode and lost with the primary, make no new call (ADR 006 wave 7); [verify-failover.py](../scripts/verify-failover.py) shows the member's case with the shipped binaries | — |
| TEN-007 | Typed refusal before any reservation | met | [`TestConcurrentCreationsNeverExceedTheOrganizationsQuotas`](../internal/controlplane/organization_quotas_test.go) (PG): agents and volume storage, 8 concurrent creations against a quota of 3, each refusal `organization_quota_exceeded` with its quota and nothing reserved; an agent that alone needs more vCPUs or RAM than the organization may run is refused at creation; [`TestConcurrentBootsNeverExceedTheOrganizationsQuotas`](../internal/controlplane/organization_quotas_test.go) (PG): active VMs, RAM and vCPUs, concurrent boots on two hosts, the boot's reservation itself refused, typed, a barrier's boot never; [`TestWorkWaitsForItsOrganizationsQuotaWithoutHoldingBackOthers`](../internal/controlplane/organization_quotas_test.go) (PG): a wake past the VM quota waits `QUEUED` (`queue_reason` `organization_quota`) without holding back another organization, in order within its own; [`TestQuotaChangesAndCreationsNeverLeaveAnAgentThatCannotBoot`](../internal/controlplane/organization_quotas_test.go) (PG); [`TestHTTPOrganizationQuotas`](../internal/api/quotas_test.go) (PG): 409 with `quota`, the refused attempt in the trail; [`TestTenantCreationPastTheHostStorageIsRefusedBeforeAnyReservation`](../internal/controlplane/organization_quotas_test.go) (PG): the host's storage limit on the tenant path; [`TestQueueDepthRefusesBeforeAnythingIsAccepted`](../internal/controlplane/instruction_queues_test.go) (PG): tasks; [`TestHardBudgetRefusesBeforeTheCallAndReleaseGivesCapacityBack`](../internal/controlplane/llm_budgets_test.go) (PG): LLM budget; [`TestAttachmentQuotaHoldsUnderConcurrencyAndExpiryFreesIt`](../internal/controlplane/attachments_test.go) (PG): attachment storage | — (work past the VM, vCPU or RAM quota waits rather than being refused, [ADR 021](adr/021-organization-quotas.md) §4; the worker's stops for a quota have no KVM run) |
| TEN-008 | OIDC/JWT or signed delegation; free-form user IDs refused | met | [`TestOperatorBootstrapFromEmptyDatabase`](../internal/api/bootstrap_test.go) (PG, real API): headers, bare names, unsigned or foreign-signed tokens, unknown subjects get 401; [`TestSignaturesAndAlgorithmConfusionAreRejected`](../internal/delegatedidentity/verifier_test.go), [`TestRequiredClaimsAndTrustBoundaries`](../internal/delegatedidentity/verifier_test.go) (unit); [`TestTenantIdentityNeedsExplicitTrustAndExistingIdentity`](../internal/controlplane/tenant_identity_test.go) (PG); [verify-install.py](../scripts/verify-install.py) (script) | — (EdDSA JWTs only; OIDC discovery is P1) |
| TEN-009 | Who, when, resource, outcome; no conversation content | met | [`TestRefusedAdministrativeAttemptsJoinTheTrail`](../internal/api/audit_refusals_test.go) (PG): a member without the role, invalid input, a missing idempotency key, a guessed identifier, a technical account and a member at a platform route are refused, and each attempt joins the organization's trail with outcome `refused`, its actor, action, target and code, never the request's body; reads, invocations and unauthenticated requests leave no event; [`TestEveryAuditedRouteIsServed`](../internal/api/audit_refusals_test.go) (unit): every route that changes something is audited or listed as not administrative; [`TestAuditTrailHoldsNoConversationContent`](../internal/controlplane/audit_content_test.go) (PG): after invocations, messages, results and a request and its reply between two agents, the trail, its export and the operator's feed hold none of their content; [`TestReplaysAndHarnessImportsJoinTheAuditFeeds`](../internal/controlplane/audit_content_test.go) (PG): replays of dead letters in the organization's trail, harness imports and the operator's replays in the operator's feed; [`TestAuditFeedIsCompletePagedAndMetadataOnly`](../internal/controlplane/audit_feed_test.go) (PG): actor, time, target, action; [`TestOperatorCommandsAreDryRunAndAudited`](../internal/controlplane/operations_test.go) (PG): the operator's commands with their outcome, refusals included; [`TestPlatformCredentialIsAudited`](../internal/controlplane/operator_bootstrap_test.go) (PG); [`TestOrganizationAuditFailureRollsBackCreationAndDisable`](../internal/controlplane/organizations_test.go) (PG) | — (a refusal is recorded after its answer: a record that fails is logged, `audit_refusal_unrecorded`, not retried; ADR 014 §10) |

### Isolation

The sentence under the table: isolation also covers search, metrics, logs,
attachments, download URLs and statistics; the organization comes from
authentication, never from a request body.

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| ISO-1 | Search | met | [`TestPeerRequestsAndSearchStayInsideOneDomain`](../internal/controlplane/authorization_test.go) (PG); [`TestDirectorySearchFromAVMIsCheckedAgainstPostgreSQL`](../internal/controlplane/agent_directory_test.go) (PG): another organization's agent with the same skill is never returned; [`TestPublisherAgainstThePrivateDirectory`](../internal/directory/services_test.go) (interop) | — |
| ISO-2 | Metrics | met | [`TestHTTPTelemetry`](../internal/api/telemetry_test.go) (PG): route patterns only; [`TestRevocationIsPendingUntilTheReplicaHoldsIt`](../internal/api/revocations_test.go) (PG): the pending revocations are counted without a label; [`TestModelCallMetricsAndEventsCarryNoTenant`](../internal/worker/llm_telemetry_test.go) (unit) | — (metrics are the operator's; no tenant route serves them) |
| ISO-3 | Logs | met | [`TestHTTPTelemetry`](../internal/api/telemetry_test.go) (PG); [`TestAPIBinariesBootstrapServeAndShutdown`](../internal/api/server_test.go) (PG): the API process log holds no token, name or DSN; [`TestFreeTextNeverReachesMetricsOrLogs`](../internal/telemetry/telemetry_test.go) (unit) | — |
| ISO-4 | Attachments | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): 404 to other callers; [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): another organization's file cannot be read or attached | — |
| ISO-5 | Download URLs | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): another organization's owner gets 404 on both link routes, and a bearer opens no download; [`TestHTTPTemporaryDownloadLinks`](../internal/api/downloads_test.go) (PG): only the sender gets a link, which opens its one resource and nothing once the right is gone; [`TestDownloadLinksExpireAndStaySealed`](../internal/controlplane/download_links_test.go) (unit): another installation's link opens nothing | — |
| ISO-6 | Statistics | partial | [`TestThePlatformSetsAnOrganizationsQuotas`](../internal/controlplane/organization_quotas_test.go) (PG): another organization's agent and running VM are absent from the quota usage, which counts exactly the organization's own; [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): another organization's owner reads `GET /v1/organizations/current/quotas` without the first organization's identifier, and only the status of `GET /v1/llm/usage` and `GET /v1/queue` | No test asserts that another organization's numbers are absent from `GET /v1/llm/usage` and `GET /v1/queue`. The code filters by organization |
| ISO-7 | Organization from authentication, never from a body | met | [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): an access revocation is read only by its organization's administrators and auditors, 404 for another organization and for the platform; [`TestHTTPMembersTenantAndCredentialBoundaries`](../internal/api/members_test.go) (PG): `tenant_id` in a body gets 400, in a query is ignored; [`TestHTTPTeamsLifecycleAndInput`](../internal/api/teams_test.go), [`TestHTTPDelegationCurrentOrganizationAndBoundaries`](../internal/api/delegated_identity_test.go) (PG); [`TestVerifiedIdentityComesFromConfiguredTrust`](../internal/delegatedidentity/verifier_test.go) (unit) | — |

### Harness registry and supply chain

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| REG-001 | Asynchronous, tracked by `operation_id` | met | [`TestHarnessImportBecomesAnImmutableRelease`](../internal/controlplane/harness_registry_test.go) (PG): 202 `IMPORTING`, claimed by a worker, then `READY`; [`TestHTTPHarnessImportsAreForThePlatformAndReleasesForMembers`](../internal/api/harness_test.go) (PG): 202, replay, `GET /v1/harness-imports/{id}`; [`TestWorkerImportsVerifiedPackagesIntoTheCache`](../internal/worker/registry_test.go) (PG) | — (tracked by the import's `id`, not a field named `operation_id`) |
| REG-002 | Same test passes on GHCR and a local registry | partial | [`TestPackageRoundTripThroughARegistryWithTokenAndCDN`](../internal/ociregistry/registry_test.go) (unit): a registry with a token service and a CDN redirect, as GHCR does; [`TestSignedImportsNeedATrustedPublisher`](../internal/ociregistry/signature_test.go) (unit): with and without the referrers API; the Dagger `check` in CI, against `registry:2` | No run against GHCR itself (REG-02) |
| REG-003 | Tampered or incompatible package rejected | met | [`TestTamperedOrIncompatiblePackagesAreRejected`](../internal/ociregistry/registry_test.go) (unit): altered blob, wrong type, extra or reordered layer, oversized image, aarch64, lying checksums; [`TestManifestIsStrict`](../internal/harnesspkg/package_test.go) (unit); [`TestWorkerImportsVerifiedPackagesIntoTheCache`](../internal/worker/registry_test.go) (PG): `REJECTED integrity`, nothing cached | — |
| REG-004 | Arbitrary or SSRF-style references refused | met | [`TestPolicyRefusesUnapprovedAndUnsafeReferences`](../internal/ociregistry/registry_test.go) (unit): unapproved registry, link-local address, unpinned reference, loopback dial; [`TestRedirectsAndTokensOnlyToApprovedHosts`](../internal/ociregistry/registry_test.go) (unit); [`TestWorkerImportsVerifiedPackagesIntoTheCache`](../internal/worker/registry_test.go) (PG): `REJECTED policy` with no pull | — |
| REG-005 | `name:version` maps to a stable digest; no overwrite | met | [`TestHarnessImportBecomesAnImmutableRelease`](../internal/controlplane/harness_registry_test.go) (PG): another digest is `REJECTED version_conflict`; [`TestConcurrentImportsOfOneVersionYieldOneRelease`](../internal/controlplane/harness_registry_test.go) (PG) | — |
| REG-006 | Two agents share one image; active releases kept | met | [`TestProductWorkerTenantRunsAnImportedHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): two VMs' jails hold the same inode, read-only; [`TestProductWorkerTenantUpgradesAndRollsBackAnImportedHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): eviction keeps the running release; [`TestEvictionKeepsEveryPackageAnAgentMayBoot`](../internal/worker/registry_test.go) (PG) | — |
| REG-007 | Only pull, validation and boot observed | partial | [`TestProductWorkerTenantRunsAnImportedHarness`](../internal/worker/product_registry_integration_test.go), [`TestProductWorkerTenantRunsAPythonHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): packages built off-host, pulled, verified and booted | Nothing observes that the host does nothing else: true by construction, not by a check |
| REG-008 | Queryable; errors leak no secret | met | [`TestRejectedImportLeaksNoRegistrySecret`](../internal/worker/registry_secrets_test.go) (PG): a hostile private registry echoes the password, the Basic header and the token in its bodies, headers and challenges while it refuses them; the imports end `REJECTED` (`access_denied`) or retried, and no table, API answer, API event or metric, nor any error the importer met, holds a secret; [`TestHarnessImportBecomesAnImmutableRelease`](../internal/controlplane/harness_registry_test.go) (PG): `IMPORTING`, `READY`, `REJECTED`; [`TestReleasesAreListedToMembersAndDeprecatedByThePlatform`](../internal/controlplane/harness_registry_test.go) (PG): `DEPRECATED`; [`TestPrivateRegistryImportsNeedCredentials`](../internal/worker/registry_test.go) (PG) | — (the worker logs an import's retry as a bare event, `harness_import_retry`) |
| REG-009 | Strict mode rejects unauthorized releases | met | [`TestSignedImportsNeedATrustedPublisher`](../internal/ociregistry/signature_test.go) (unit): unsigned or stranger-signed refused before download; [`TestSignedImportsRecordTheirPublisher`](../internal/worker/registry_test.go) (PG): `REJECTED signature`; [`TestPublisherKeysComeFromProtectedFiles`](../internal/worker/registry_credentials_test.go) (unit) | — (key signatures only; attestations and keyless signatures are not verified) |
| REG-010 | Same protocol; no platform dependency on them | met | [`TestProductWorkerTenantRunsAPythonHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): a Python harness imported like any package; [`TestProductWorkerTenantRunsAnImportedHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): Go; the Dagger `check` in CI builds both | — |

### Capsules and runtime

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| RUN-001 | `STOPPED`; no Firecracker process | met | [`TestDesiredStateFollowsTheLifecycleLedgerNotTheWish`](../internal/controlplane/instruction_queues_test.go) (PG): a new agent is `STOPPED`; [`TestProductWorkerProvisioningAndEncryptedWake`](../internal/worker/product_provisioning_integration_test.go) (KVM 2026-11-15): no VM after provisioning | — (creation boots a restricted VM to format the volume, then stops it) |
| RUN-002 | KVM, jailer, cgroups checked; `READY` | needs KVM | [`TestProductWorkerJailsEachVMAndLeavesNothingBehind`](../internal/worker/product_jail_integration_test.go) (KVM, never run): in a product wake, the agent reads `READY`, and its VMM runs as the agent's UID and GID, without groups or capabilities, under seccomp, chrooted in its jail, as PID 1 of its own PID namespace, in its own mount and network namespaces and its own cgroup with the plan's `memory.max`, `cpu.max` and `pids.max`, with 256 open files at most, and holds a KVM VM; [`TestProductGuestEncryptedPersistenceAndIsolation`](../internal/runtime/product_guest_integration_test.go) (KVM 2026-11-15): `memory.max` and `cpu.max` match the plan; [`TestProductWorkerContractOutagePreservesCensusAndMaintenance`](../internal/worker/product_contract_integration_test.go) (KVM 2026-11-15): `READY` only with a contract; [`TestProvisionedResourcesReachVMConfiguration`](../internal/runtime/firecracker_provisioning_test.go) (unit) | The jail test has never run. `/dev/kvm` itself is checked by the preflight (RUN-012) |
| RUN-003 | Concurrent wakes yield one generation | met | [`TestPlacementConcurrentLeasesAndFencing`](../internal/controlplane/placements_test.go) (PG): 12 concurrent claims, one winner; [`TestFirecrackerConcurrentStartAndGenerations`](../internal/runtime/firecracker_integration_test.go) (KVM 2026-11-09): 8 concurrent starts, one VMM; [`TestPostgresKVMConcurrentStartAdoptionAndFencedStop`](../internal/worker/placements_integration_test.go) (KVM 2026-11-09) | — |
| RUN-004 | No process or RAM left; data kept | met | [`TestProductWorkerProvisioningAndEncryptedWake`](../internal/worker/product_provisioning_integration_test.go) (KVM 2026-11-15): clean stop, no VM left, the stored effect replayed; [`TestQuiesceStopRequiresGuestACKAndPhysicalRetirement`](../internal/worker/quiesce_test.go) (PG) | — (memory is inferred from the VMM census and the cgroup removal) |
| RUN-005 | Audited; no volume left mounted | met | [`TestProductWorkerTwoOwnersPrivateExchange`](../internal/worker/product_peers_integration_test.go) (KVM 2026-11-15): queued work canceled, key revoked, volume file gone, no VM; [`TestLifecycleCommandsAreAuditedOnceAndRaceSafely`](../internal/controlplane/instruction_queues_test.go) (PG); [`TestConcurrentDeletionAndAdmission`](../internal/controlplane/revocation_test.go) (PG); [`TestVolumeRemovalChecksIdentityAndWriterExclusion`](../internal/volumestore/remove_test.go) (unit) | — (backup expiry "per policy": see OPR-18) |
| RUN-006 | Reconciled after a worker crash | met | [`TestPostgresKVMWorkerCrashAfterDatabaseConfirmation`](../internal/worker/placements_integration_test.go) (KVM 2026-11-09): after a SIGKILL the next generation starts; [`TestFirecrackerWorkerCrash`](../internal/runtime/firecracker_integration_test.go) (KVM 2026-11-09); [`TestDesiredStateFollowsTheLifecycleLedgerNotTheWish`](../internal/controlplane/instruction_queues_test.go) (PG) | — (an agent that should run is not restarted automatically: CAP-02) |
| RUN-007 | A hostile agent stays within ceilings | needs KVM | [`TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest`](../internal/worker/product_limits_integration_test.go) (KVM, never run): I/O ceilings; [`TestDrivesHaveIOCeilings`](../internal/runtime/firecracker_limits_test.go), [`TestProvisionedResourcesReachVMConfiguration`](../internal/runtime/firecracker_provisioning_test.go) (unit) | The I/O test has never run. No hostile-guest test for CPU, memory, processes or time |
| RUN-008 | Nothing left for another capsule | needs KVM | [`TestProductWorkerJailsEachVMAndLeavesNothingBehind`](../internal/worker/product_jail_integration_test.go) (KVM, never run): after a stop, no process runs as the agent's UID, and no jail, cgroup, socket, platform lock or boot credentials remain; the UID owns the agent's volume alone, and nothing once the agent is deleted; the next agent gets another UID; [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): distinct VM, UID and volume; [`TestProductGuestEncryptedPersistenceAndIsolation`](../internal/runtime/product_guest_integration_test.go) (KVM 2026-11-15): a volume alias refused; [`TestRecoverIsolatesAFailingAgent`](../internal/runtime/firecracker_removal_test.go) (unit) | The test has never run. The VM's log stays on the host, readable by root alone. `verify-vm-isolation.py` runs its own jailer lab, not the product runtime |
| RUN-009 | Write, stop, restart, read the same value | met | [`TestProductWorkerTenantRunsAPythonHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): the harness's counter continues after sleep and wake; [`TestProductWorkerTwoOwnersPrivateExchange`](../internal/worker/product_peers_integration_test.go), [`TestProductGuestEncryptedPersistenceAndIsolation`](../internal/runtime/product_guest_integration_test.go) (KVM 2026-11-15) | — |
| RUN-010 | Execution observed only in guests | met | [`TestProductWorkerTenantRunsAnImportedHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): the harness exists only on the guest's drive and answers; [`TestAPILinksNoRuntimeWorkerOrGuestCode`](../cmd/agentcapsule-api/imports_test.go), [`TestWorkerLinksNoHarnessCode`](../cmd/agentcapsule-api/imports_test.go) (unit, `go list -deps`): neither the API nor the worker links a harness, the guest's init or any other code that only the guest programs link; they share the protocol, the capability names and the guest's event store format | — (a package is only parsed and handed to Firecracker; that the worker starts no program but the jailer and the archive fetch is read in the code, not checked) |
| RUN-011 | `FAILED` or `QUEUED`; no spawn loop | met | [`TestAnAgentWhoseGuestKeepsFailingIsFailed`](../internal/controlplane/restart_budgets_test.go) (PG): `FAILED` after the restart budget, no more boots; [`TestAFullHostAdmitsWaitingWorkInArrivalOrder`](../internal/controlplane/capacity_queue_test.go) (PG): an agent waiting for a VM slot shows `QUEUED`, and no longer once admitted; [`TestAFailedAgentDoesNotWaitForCapacity`](../internal/controlplane/capacity_queue_test.go) (PG); [`TestCrashesSpendTheRestartBudget`](../internal/controlplane/restart_budgets_test.go), [`TestGuestFailuresAreCountedAndLogged`](../internal/worker/restart_budget_test.go) (PG) | — ([`TestProductWorkerStopsBootingAGuestThatCrashesAtBoot`](../internal/worker/product_limits_integration_test.go) (KVM) has never run) |
| RUN-012 | No Firecracker mode without `/dev/kvm` and a compatible kernel | met | [`TestKVMDevice`](../internal/preflight/preflight_test.go), [`TestKernelVersion`](../internal/preflight/preflight_test.go), [`TestMandatoryOnAGoodFakeHost`](../internal/preflight/preflight_test.go) (unit): the checks fail on a bad device or an old kernel; [verify-install.py](../scripts/verify-install.py) (script): the worker binary refuses to start when a mandatory check fails, and passes every check on this machine with the artifacts | — (not run as root, nor on a production server) |

### Invocations and events

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| EVT-001 | An API crash after ACK loses nothing | met | [`TestAPIKilledAfterAcceptanceLosesNoInvocation`](../internal/api/acceptance_crash_test.go) (PG, real process): the API process dies by SIGKILL right after writing its 202 to `POST /v1/agents/{id}/invocations` or `/messages`; a new API process answers the invocation under its ID, replays the same answer to the same Idempotency-Key without creating anything, and a dispatch delivers it once with its result; [`TestInvocationDatabaseRecovery`](../internal/controlplane/invocation_recovery_test.go) (PG, WAL recovery): an invocation accepted before an immediate shutdown of PostgreSQL survives its recovery, replays and is delivered once; [`TestAPIProcessCrash/after-commit`](../internal/controlplane/store_test.go) (PG); [`TestReplyAPIProcessCrash`](../internal/controlplane/replies_test.go) (PG); [`TestDurableDatabaseRestart`](../internal/controlplane/store_test.go) (PG, WAL recovery) | — (a database crash is an immediate shutdown with WAL recovery, not a power loss: VAL-01) |
| EVT-002 | `STOPPED → READY → BUSY`, unattended | needs KVM | [`TestProductWorkerWakesQueuesAndKeepsAWorkingAgentAwake`](../internal/worker/product_idle_integration_test.go) (KVM, never run): an invocation for a stopped agent, without a wake command: the agent reads `STOPPED`, then `READY` with its invocation `working`; on a full host, another stopped agent's work makes it `QUEUED` (ADR 017) while the first computes, then `READY` once the slot frees, and it answers; [`TestProductWorkerNightlyVolumeArchives`](../internal/worker/product_archives_integration_test.go) (KVM 2026-11-15): an invocation wakes a stopped agent and completes, without a wake call; [`TestProductWorkerTenantAgentsTalkOverA2A`](../internal/worker/product_adapter_integration_test.go) (KVM 2026-11-15): a request wakes its recipient | The test has never run. `BUSY` is not a state of the code: the test asserts what the code shows, a `READY` agent with a `working` invocation (product owner question on the state names) |
| EVT-003 | One key, one business operation | met | [`TestConcurrentIdempotencyAndMandateBudget`](../internal/controlplane/store_test.go) (PG): 18 concurrent calls with one key, one request; [`TestInstructionRollbackConcurrentReplayAndSharedSequence`](../internal/controlplane/instructions_test.go) (PG); [`TestInvocationResourceFollowsTheRequestWithoutExposingContent`](../internal/controlplane/tenant_invocations_test.go) (PG); [`TestHTTPInstructionsOwnerOnlyAndDurableReceipt`](../internal/api/instructions_test.go) (PG): same answer, 422 on another body | — |
| EVT-004 | Never two writable copies | met | [`TestPlacementConcurrentLeasesAndFencing`](../internal/controlplane/placements_test.go) (PG); [`TestVMGenerationGuardsIncludingIdempotentReplay`](../internal/controlplane/vm_authorization_test.go) (PG); [`TestFirecrackerConcurrentStartAndGenerations`](../internal/runtime/firecracker_integration_test.go), [`TestFirecrackerCrossRegistryVolumeAlias`](../internal/runtime/firecracker_integration_test.go) (KVM 2026-11-09): one writer per volume | — |
| EVT-005 | No unbounded loop | met | [`TestExhaustedDeliveryFencesLateWorkerAndNotifiesSender`](../internal/controlplane/delivery_test.go) (PG): the attempt limit ends the delivery; [`TestInstructionRetirementFencesDelayedEffectAndKeepsUnknownOutcome`](../internal/controlplane/instruction_delivery_test.go) (PG); [`TestDeadDeliveryIsCountedAndLogged`](../internal/worker/dead_delivery_test.go) (PG); [`TestWorkFairRetryLeaseAndConcurrentClaims`](../internal/controlplane/work_test.go) (PG): retry delay honored | — (the backoff formula has no unit test; a dead letter goes back only by a person's replay: [`TestTheOperatorReplaysADeadLetter`](../internal/controlplane/instruction_replays_test.go) (PG)) |
| EVT-006 | Expired tasks never run | met | [`TestInvocationTTLAndExpiryAreVisibleAndDistinct`](../internal/controlplane/instruction_queues_test.go) (PG): an expired head ends `expired` without a result; [`TestExpirationWaitsForEffectAndAtomicNotification`](../internal/controlplane/delivery_test.go) (PG): the old envelope is fenced; [`TestQueueDepthRefusesBeforeAnythingIsAccepted`](../internal/controlplane/instruction_queues_test.go), [`TestQueueTenantLimitSpansAgentsAndIsolatesTenants`](../internal/controlplane/instruction_queues_test.go) (PG): agent and organization limits | — (priority left the MVP: ADR 007) |
| EVT-007 | Resumes, or expires with a clear error | met | [`TestAFullHostAdmitsWaitingWorkInArrivalOrder`](../internal/controlplane/capacity_queue_test.go) (PG): work waits for a VM slot, in arrival order across organizations, and boots when one frees; [`TestWorkWaitingPastItsTTLNeverRunsAndLeavesTheQueue`](../internal/controlplane/capacity_queue_test.go) (PG): past its deadline it ends `expired` with `capacity_unavailable`; [`TestInterruptedWorkIsResumed`](../internal/controlplane/capacity_queue_test.go) (PG); [`TestDeliveryBackpressureDoesNotConsumeAttempt`](../internal/controlplane/delivery_admission_test.go) (PG): blocked admission waits, then delivers | — |
| EVT-008 | Runs no earlier than due | met | [`TestScheduledInvocationIsNeverReleasedBeforeItsTimeAndExactlyOnce`](../internal/controlplane/scheduling_test.go) (PG): nothing released before the due time, once after it; [`TestScheduleBoundsCancellationAndQueueAccounting`](../internal/controlplane/scheduling_test.go) (PG) | — |
| EVT-009 | `GET /v1/operations/{id}` gives state and result or error | met | [`TestHTTPInstructionResultFromRealHarnessAfterLostACK`](../internal/api/instruction_process_test.go) (PG, real harness process): 404 before the result, then 200 with it; [`TestHTTPLifecycleCommandsArePrivateAndRemainObservable`](../internal/api/lifecycle_test.go) (PG): state and error code; [`TestProductWorkerTenantAsyncInvocationWithFileAndModel`](../internal/worker/product_tenant_integration_test.go) (KVM 2026-11-15): polled to `completed` | — (the result is at `/v1/operations/{id}/result` and `/v1/invocations/{id}/result`) |
| EVT-010 | No stop during uncheckpointed work | needs KVM | [`TestProductWorkerWakesQueuesAndKeepsAWorkingAgentAwake`](../internal/worker/product_idle_integration_test.go) (KVM, never run): ten minutes past its idle timeout, the idle loop does not put to sleep an agent whose invocation works on a model call, and stops another agent once it has nothing to do; [`TestWorkingAgentIsNotPutToSleepByItsIdlePolicy`](../internal/controlplane/invocation_completion_test.go) (PG); [`TestWorkKeepsAnAgentAwake`](../internal/controlplane/idle_policy_test.go), [`TestIdleAgentSleepsOnceAfterItsDelayAndNeverBefore`](../internal/controlplane/idle_policy_test.go) (PG); [`TestWorkStopsOnlyVMsThatAreNotComputing`](../internal/controlplane/capacity_queue_test.go) (PG): a full host never stops a computing VM; [`TestQuiesceStopRequiresGuestACKAndPhysicalRetirement`](../internal/worker/quiesce_test.go) (PG) | The KVM test has never run. Its work is a model call in flight, so it does not tell the `working` invocation and the model call apart (the PG test does). Work the platform cannot see is not covered |

### LLM gateway

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| LLM-001 | No mandatory provider | met | [`TestEstimatedCostIsExactAtTheBounds`](../internal/controlplane/llm_cost_test.go) (PG): three aliases on two providers in one organization; [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): an organization without a provider runs its agent; [`TestModelBridgeIsUnavailableUntilEnabled`](../internal/worker/llm_errors_test.go) (unit) | — |
| LLM-002 | Mock tests plus optional live tests | partial | [`TestOpenAIAdapterWireFormatAndUsage`](../internal/llmgateway/gateway_test.go), [`TestAnthropicAdapterWireFormat`](../internal/llmgateway/gateway_test.go), [`TestForwardAnthropicCountsCachedInput`](../internal/llmgateway/forward_test.go) (unit); [`TestLiveOfficialSDKsThroughTheModelEndpoint`](../internal/agentadapter/live_test.go) (optional, `verify-adapter.py` against a local model) | No live test against Anthropic's own API (LLM-02); no recorded live run of the `Complete` path of the Anthropic adapter |
| LLM-003 | No key in volumes, snapshots or traces | met | [`TestProviderKeysReachOnlyTheProvider`](../internal/api/secrets_leak_test.go) (PG, real authority service): three planted keys (created, rotated, Anthropic) and real gateway calls to a mock provider that echoes the key in every refusal (401, 429, 500, a timeout, forwarded requests, a hard budget), from two organization agents over their platform channels; no form of a key (whole, fragment, hex, base64) is in any row of the schema, the API's and the worker's logs and metrics, the HTTP answers, what each guest received and its volume archive, or the authorities' catalogue, replica and a snapshot taken after the calls; [`TestLLMProviderSecretsStayWriteOnlyAndEncrypted`](../internal/controlplane/llm_providers_test.go) (PG): the stored ciphertext, the answers, the audit and the stored receipt hold no key; [`TestLLMBridgeCarriesOnlyAnAliasAndTypedOutcomes`](../internal/capsuleprotocol/platform_test.go) (unit): a key never crosses to the VM; [`TestProductWorkerTenantAsyncInvocationWithFileAndModel`](../internal/worker/product_tenant_integration_test.go) (KVM 2026-11-15): the key is added on the host | — (the archived image stands for the guest's volume: a LUKS volume a real guest wrote needs KVM; PostgreSQL's WAL and backups are not searched, only its rows; there is no distributed tracing: the traces are the logs and metrics) |
| LLM-004 | Unauthorized agents refused | met | [`TestDeniedAliasNeverReachesTheProvider`](../internal/controlplane/llm_access_test.go) (PG): no reservation, no provider call; [`TestListedAliasServesOnlyGrantedAgentsAndTeams`](../internal/controlplane/llm_access_test.go) (PG); [`TestModelCallFromAVMIsBoundToItsTenantAndPlacement`](../internal/controlplane/llm_vm_test.go) (PG): a stale VM refused; [`TestPlatformChannelEnforcesCapabilities`](../internal/capsuleprotocol/platform_capability_test.go) (unit): a model call without `llm.invoke` is refused before it reaches the gateway; [`TestEffectiveCapabilitiesAreTheIntersection`](../internal/controlplane/capabilities_test.go) (PG) | — ([`TestProductWorkerEnforcesCapabilities`](../internal/worker/product_content_integration_test.go) (KVM) has never run) |
| LLM-005 | Per-period metrics; hard and soft caps | met | [`TestAliasBudgetsBindOnlyTheirModel`](../internal/controlplane/llm_periods_test.go) (PG): a budget on an alias, alone or for one agent, binds only the calls to that alias, hard or soft, and the usage is reported per agent and per alias; [`TestBudgetPeriodsRollOver`](../internal/controlplane/llm_periods_test.go) (PG): once its UTC day or month rolls over, a period's calls stop counting, the hard cap admits again and the usage starts from zero; [`TestScopedAndSoftBudgets`](../internal/controlplane/llm_budgets_test.go) (PG): an agent's hard cap refuses, an organization's soft cap flags; [`TestHardCostBudgetReservesSettlesAndRefusesBeforeTheProvider`](../internal/controlplane/llm_cost_test.go), [`TestAgentCostBudgetAndSoftCostCap`](../internal/controlplane/llm_cost_test.go) (PG); [`TestModelCallMetricsAndEventsCarryNoTenant`](../internal/worker/llm_telemetry_test.go) (unit) | — (the periods are the UTC day and month; the code has no hourly budget) |
| LLM-006 | Quota errors explicit; no reboot loop | met | [`TestModelErrorsReachTheGuestAndLeaveItsVMRunning`](../internal/worker/llm_quota_test.go) (PG): through capsule-init's local bridge, the boot's mTLS platform channel and the worker's platform API, a hard budget, a 429, a provider refusal and an outage with an open breaker reach the guest as `quota_exceeded`, `rate_limited`, `rejected` and `unavailable`; the placement stays the same running boot, no guest failure counts against a restart budget smaller than the errors, no job appears, a dispatch pass changes nothing, no boot is counted, and the next call succeeds; [`TestModelBridgeErrorsCrossAsEnumeratedCodesOnly`](../internal/worker/llm_errors_test.go) (unit): `quota_exceeded`, `rate_limited`; [`TestPlatformOutcomesBecomeSDKErrors`](../internal/agentadapter/model_test.go) (unit); [`TestRetriesOnlyBeforeAcceptanceAndNeverOnDefiniteRefusal`](../internal/llmgateway/gateway_test.go), [`TestBreakerOpensThenProbesOnce`](../internal/llmgateway/gateway_test.go) (unit) | — (a test runtime stands for the host driver: Firecracker's admission and control after a model error run only on KVM, and no product test makes a guest's model call fail) |
| LLM-007 | Effective on the next request | met | [`TestLLMRotationAndDisableApplyToTheNextCall`](../internal/controlplane/llm_providers_test.go) (PG): the next route resolution uses the new key, a disabled provider is gone; [`TestLLMRoutesDoNotCrossTenantsAndAliasDisableIsImmediate`](../internal/controlplane/llm_providers_test.go) (PG); [`TestLLMProviderEndpointsNeverReturnTheCredential`](../internal/api/llm_test.go) (PG) | — (the key is resolved at each call; no test checks the header sent after a rotation) |
| LLM-008 | Redaction tests pass | met | [`TestNoSecretInA2AMessagesOrLogsAroundAModelCall`](../internal/api/secrets_leak_test.go) (PG): during real gateway calls and a request and its reply between two agents of an organization, the events delivered to both agents, the answers on their platform channels (model calls, `DescribeAgent`, `RequestStatus`, submission, reply, completion), the API's, the worker's and the process's logs and the metrics hold no provider key, platform credential, service token or delegation JWT, and no table holds a bearer token or JWT; [`TestLLMProviderEndpointsNeverReturnTheCredential`](../internal/api/llm_test.go) (PG): API answers; [`TestFreeTextNeverReachesMetricsOrLogs`](../internal/telemetry/telemetry_test.go) (unit): metrics and logs; [`TestLLMBridgeCarriesOnlyAnAliasAndTypedOutcomes`](../internal/capsuleprotocol/platform_test.go) (unit) | — (the A2A messages are those the platform delivers; the bytes on the SLIM link between hosts and a real VM's A2A endpoint are not searched) |

### Discovery and inter-agent communication

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| A2A-001 | Updated when capabilities change | met | [`TestPublisherAgainstThePrivateDirectory`](../internal/directory/services_test.go) (interop): the record passes OASF 1.1.0, a skill change publishes a new record; [`TestDirectoryProfilesAreGovernedAndPublishedByRevision`](../internal/controlplane/agent_directory_test.go) (PG); [`TestRecordPublishesOnlyTheDescribedFields`](../internal/directory/directory_test.go) (unit) | — (capabilities are the skills the organization declares; the harness's never feed the record) |
| A2A-002 | Skill search works while `STOPPED` | met | [`TestProductWorkerTenantFlagshipJourney`](../internal/worker/product_flagship_integration_test.go) (KVM 2026-11-15): B asleep, A finds it by skill from its VM; [`TestPublisherAgainstThePrivateDirectory`](../internal/directory/services_test.go) (interop) | — |
| A2A-003 | Other organizations invisible | met | [`TestDirectorySearchFromAVMIsCheckedAgainstPostgreSQL`](../internal/controlplane/agent_directory_test.go) (PG); [`TestPublisherAgainstThePrivateDirectory`](../internal/directory/services_test.go) (interop): another organization's scope finds nothing; [`TestDescribeAgentFromAVMFollowsTheRecipientRules`](../internal/controlplane/peer_reads_test.go) (PG) | — (the filter is the organization and discoverability; there is no assignment filter) |
| A2A-004 | Agent Card and transitions tested on the pinned spec | met | [`TestTheOfficialA2AClientSendsARequestAndGetsTheReply`](../internal/agentadapter/a2a_test.go) (unit): the official a2a-go client checks the card and the states; [`TestRequestsThatEndWithoutAReply`](../internal/agentadapter/a2a_test.go), [`TestTheA2AEndpointRefusals`](../internal/agentadapter/a2a_test.go), [`TestCardsAndDiscovery`](../internal/agentadapter/a2a_test.go) (unit) | — |
| A2A-005 | Visible in the private SLIM node | needs KVM | [`TestBridgesCarryDeliveriesThroughTheNode`](../runtime/slimbridge/services_test.go) (interop); [`TestA2AOverSLIMThroughThePrivateNode`](../runtime/interop/a2aslim/a2aslim_test.go) (interop); [`TestProductWorkerTenantAgentsTalkOverSLIM`](../internal/worker/product_slim_integration_test.go) (KVM 2026-11-15; its check of the node's log never run): the node's own log shows it forwarding the request to the recipient's name, then the reply to the sender's | The node-log check has never run. The campaign's node logs its message processing; a host's node, at INFO, logs its start only ([interop.md](interop.md#the-slim-bridge-int-04)) |
| A2A-006 | Worker crash loses no accepted task | met | [`TestDeliveryWorkerProcessCrash`](../internal/controlplane/delivery_test.go) (PG): a SIGKILL before or after the commit, the request delivered once; [`TestWorkDatabaseRecovery`](../internal/controlplane/work_test.go) (PG, WAL recovery); [`TestDispatchWorkerCrashRecovery`](../internal/worker/dispatch_integration_test.go) (KVM 2026-11-09) | — |
| A2A-007 | B answers from its own VM | met | [`TestProductWorkerTenantAgentsTalkOverA2A`](../internal/worker/product_adapter_integration_test.go) (KVM 2026-11-15): B asleep, A's request wakes it, B's own A2A server answers; [`TestProductWorkerTenantAgentsTalkOverSLIM`](../internal/worker/product_slim_integration_test.go) (KVM 2026-11-15) | — |
| A2A-008 | Delivery is not success | met | [`TestTheOfficialA2AClientSendsARequestAndGetsTheReply`](../internal/agentadapter/a2a_test.go) (unit): completed only with the reply; [`TestDeliveryConcurrentClaimsFIFOAndLostAck`](../internal/controlplane/delivery_test.go) (PG): delivered stays `PROCESSING`; [`TestExhaustedDeliveryFencesLateWorkerAndNotifiesSender`](../internal/controlplane/delivery_test.go), [`TestExpirationWaitsForEffectAndAtomicNotification`](../internal/controlplane/delivery_test.go) (PG) | — ("delivered" and "working" are one state, `PROCESSING`) |
| A2A-009 | ACL, TTL, hops, wake budget tested | met | [`TestTheA2AEndpointRefusals`](../internal/agentadapter/a2a_test.go) (unit): no request while answering a peer; [`TestPeerEnvelopeCannotCarryOwnerAuthority`](../internal/controlplane/peer_payloads_test.go) (unit); [`TestConcurrentIdempotencyAndMandateBudget`](../internal/controlplane/store_test.go) (PG): fan-out bounded by the mandate; [`TestRequestsBetweenAgentsWakeWithinTheOrganizationsBudget`](../internal/controlplane/peer_wakes_test.go) (PG) | — (one hop by construction: no hop counter, no cycle test) |
| A2A-010 | A gets it, after waking if needed | needs KVM | [`TestProductWorkerSenderWakesForTheReply`](../internal/worker/product_replies_integration_test.go) (KVM, never run): A asks B, then sleeps before the reply exists; B replies; the reply wakes A, whose VM receives it and posts it to A's owner, with no wake command; [`TestProductWorkerTenantAgentsTalkOverA2A`](../internal/worker/product_adapter_integration_test.go) (KVM 2026-11-15): A gets B's reply after B woke; [`TestTenantAgentsExchangePrivateContentForTheirRequester`](../internal/controlplane/tenant_peer_payloads_test.go) (PG); [`TestA2AGetTaskCompletesAfterDeadReply`](../internal/agentadapter/a2a_test.go) (unit) | The test has never run. It uses the owners' domain and the reference harness: an A2A agent (capsule-adapter) put to sleep while its task waits is not covered. [`TestProductWorkerRestoresAgentToAgentExchange`](../internal/worker/product_restore_integration_test.go) (KVM) has never run |
| A2A-011 | Only authorized descriptions indexed | met | [`TestRecordPublishesOnlyTheDescribedFields`](../internal/directory/directory_test.go) (unit); [`TestDirectoryProfilesAreGovernedAndPublishedByRevision`](../internal/controlplane/agent_directory_test.go) (PG): hidden, deleted or suspended agents withdrawn; [`TestHTTPAgentDirectoryProfile`](../internal/api/agent_directory_test.go) (PG); [`TestPublisherAgainstThePrivateDirectory`](../internal/directory/services_test.go) (interop) | — |
| A2A-012 | Explicit attempts rejected | met | [`TestPeerRequestsAndSearchStayInsideOneDomain`](../internal/controlplane/authorization_test.go) (PG): a request to another organization's agent is refused; [`TestDescribeAgentFromAVMFollowsTheRecipientRules`](../internal/controlplane/peer_reads_test.go) (PG); [`TestTheA2AEndpointRefusals`](../internal/agentadapter/a2a_test.go) (unit) | — (no cross-organization attempt from a VM on KVM) |

### Content, capabilities and clients

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| EXT-001 | Invocation works | met | [`TestHTTPInvocationCarriesStructuredJSON`](../internal/api/content_test.go) (PG): text and JSON parts, the JSON validated at the API, through the transit encryption to the agent as a JSON part, and back in the result; [`TestJSONContentReachesTheRunAndComesBack`](../internal/agentadapter/content_test.go), [`TestContentPartsCarryStructuredJSON`](../internal/capsuleprotocol/content_test.go) (unit); [`TestProductWorkerTenantAsyncInvocationWithFileAndModel`](../internal/worker/product_tenant_integration_test.go) (KVM 2026-11-15): a text invocation | — (JSON on KVM, [`TestProductWorkerDeliversJSONContent`](../internal/worker/product_content_integration_test.go), has never run) |
| EXT-002 | Right agent only; cross-tenant refused | met | [`TestHTTPAttachmentReachesOnlyTheAgentItWasUploadedFor`](../internal/api/content_test.go) (PG): a file uploaded for agent A, attached by the same member to an invocation of agent B of the same organization, gets `409 attachment_unavailable`; nothing is admitted and the file stays for A; [`TestAttachmentReachesOnlyItsRunningInvocationEncrypted`](../internal/controlplane/attachments_test.go) (PG): only the recipient's current VM, while its invocation runs; [`TestAttachmentUploadRulesAreEnforcedBeforeStoring`](../internal/controlplane/attachments_test.go) (PG): MIME, size, hash; [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG): another organization gets 404 on the file; [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): cross-tenant refused | — |
| EXT-003 | Matches manifest and policy | met | [`TestHTTPCapabilityCatalogAndPolicies`](../internal/api/content_test.go) (PG): an agent's catalog shows what its harness requests, what its organization and the agent allow, and the effective set; [`TestEffectiveCapabilitiesAreTheIntersection`](../internal/controlplane/capabilities_test.go), [`TestReleasesRecordTheCapabilitiesTheyRequest`](../internal/controlplane/capabilities_test.go) (PG); [`TestManifestDeclaresItsCapabilities`](../internal/harnesspkg/package_test.go) (unit); [`TestPlatformChannelEnforcesCapabilities`](../internal/capsuleprotocol/platform_capability_test.go) (unit): a call outside the effective set is refused | — ([`TestProductWorkerEnforcesCapabilities`](../internal/worker/product_content_integration_test.go) (KVM) has never run) |
| EXT-008 | Every MVP feature usable without a UI | met | [`TestHTTPExamplesRunAsWritten`](../internal/api/examples_test.go) (PG): [examples.md](api/examples.md) runs as written over HTTPS, 46 calls on 39 routes: a harness import, members, agents, assignments, invocations and their polling, files and download links, wake and sleep, held requests from other agents, a technical account and its revocation, models and budgets, the audit trail and its export, deletion; each answer is compared with the one the page shows; [`TestExampleChecksRefuseWhatTheyCannotVouchFor`](../internal/api/examples_test.go) (unit): a command the test cannot run, or an answer unlike the page's, fails it; [`TestRBACMatrixCoversEveryRoute`](../internal/api/rbac_matrix_test.go) (unit): every feature is an HTTP route; [verify-install.py](../scripts/verify-install.py) (script): the install and an organization's first steps by CLI and curl | — (the test reads curl's and jq's options rather than run the programs; teams, schedules, release changes and replays of dead letters have no example) |

### API conventions

| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| CONV-1 | Versioned `/v1` JSON over HTTPS, OpenAPI 3.1 | met | [`TestOpenAPIDescribesExactlyTheServedRoutes`](../internal/api/openapi_test.go) (unit): every route the server serves is under `/v1` and in `openapi/openapi.yaml` with each of its methods, every documented operation is served, and the RBAC matrix lists the same; [`TestHTTPExamplesRunAsWritten`](../internal/api/examples_test.go) (PG): 46 JSON answers over HTTPS, on 39 routes, hold the required fields of their documented schema and no undocumented one; [`TestAPIBinariesBootstrapServeAndShutdown`](../internal/api/server_test.go) (PG): HTTPS, clear text gets 400; [`TestProductionRefusesClearText`](../cmd/agentcapsule-api/main_test.go) (unit); CI validates `openapi/openapi.yaml` as OpenAPI 3.1; [verify-install.py](../scripts/verify-install.py) (script) | — (answers are checked on the routes of the examples, top-level fields and list items, not the fields' types) |
| CONV-2 | Bearer tokens with subject, organization and scopes | met | [`TestVerifiedIdentityComesFromConfiguredTrust`](../internal/delegatedidentity/verifier_test.go) (unit); [`TestTenantIdentityNeedsExplicitTrustAndExistingIdentity`](../internal/controlplane/tenant_identity_test.go) (PG): altered scopes or tenant refused; [`TestServiceTokenActsWithinItsRoleAndScopesOnly`](../internal/controlplane/service_accounts_test.go) (PG) | — |
| CONV-3 | `Idempotency-Key` on every mutation | met | [`TestEveryMutationNeedsAnIdempotencyKey`](../internal/api/conventions_test.go) (PG): each of the 51 mutations of the organization and platform domains, as a caller it serves: without a key `400 idempotency_key_required`, then the same call with a key succeeds; the same key and body give back the first answer with `Idempotency-Replayed: true`; another body gets `422 idempotency_key_reused`; the key on another target never gives back the first answer; [`TestIdempotencyTablesNameRealRoutes`](../internal/api/conventions_test.go) (unit); [`TestOperatorBootstrapFromEmptyDatabase`](../internal/api/bootstrap_test.go) (PG, real binaries): every route of the closed legacy domain, `PUT /v1/me/messaging-settings` among them, refuses its tokens with 401, and [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG) gives 403 to every other caller | — (`PUT /v1/me/messaging-settings` takes no key, and no credential the API accepts reaches it; the two download-link routes store nothing and take none, ADR 016) |
| CONV-4 | `202` plus `operation_id` for asynchronous work | partial | [`TestAsynchronousRoutesAnswer202WithWorkToFollow`](../internal/api/conventions_test.go) (PG): each of the 8 asynchronous routes answers 202 with the identifier of its work, and the route that follows it finds it; [`TestAsynchronousRoutesAreListed`](../internal/api/conventions_test.go), [`TestOpenAPIDocumentsTheAsynchronousRoutes`](../internal/api/openapi_test.go) (unit): the list is complete, against the routes and the document | Agent creation, deletion, wake, sleep and messages answer `operation_id`; harness imports, invocations and their replay answer `id` (an invocation's is an operation, `op_...`, which `GET /v1/operations/{id}` also follows). Adding `operation_id` is a question for the product owner |
| CONV-5 | Opaque IDs and cursors | met | [`TestIdentifiersAndCursorsAreOpaque`](../internal/api/conventions_test.go) (PG): every identifier in the answers of every `GET` route is a kind and 128 random bits (63 identifiers of 15 kinds); identifiers made in a row share no prefix; the audit cursor shows no field of its page, and a forged one gets 400; another organization's identifier, or an unknown one, as a cursor shows nothing the caller does not see without it; [`TestAuditFeedIsCompletePagedAndMetadataOnly`](../internal/controlplane/audit_feed_test.go) (PG) | — (a list goes on from the last identifier of a page; the audit's cursor is an encoded position, not encrypted) |
| CONV-6 | `application/problem+json` with a stable `code` | met | [`TestHTTPAccountsAndRoleBoundary`](../internal/api/server_test.go) (PG): 12 error cases; [`TestEveryProblemCodeIsDeclared`](../internal/api/telemetry_test.go) (unit): every code is in a closed list | — |
| CONV-7 | Bounded payloads | met | [`TestHTTPAccountsAndRoleBoundary`](../internal/api/server_test.go) (PG): a 70 kB body gets 413; [`TestHTTPTenantInvocationIsGovernedByAssignments`](../internal/api/tenant_agents_test.go) (PG): an oversized attachment gets 413; [`TestMalformedAndOversizedTokensFailWithoutIdentity`](../internal/delegatedidentity/verifier_test.go) (unit) | — |
| CONV-8 | Temporary download URLs bound to identity | met | [`TestHTTPTemporaryDownloadLinks`](../internal/api/downloads_test.go) (PG): a link is bound to the person who asked and to one resource, works without the bearer, and opens nothing once that person loses the right; [`TestDownloadLinksExpireAndStaySealed`](../internal/controlplane/download_links_test.go) (unit): it expires, shows nothing of what it opens, and stands for its principal narrowed to reading content | — |
| CONV-9 | No route forwards a raw Firecracker or shell command | met | [`TestAPILinksNoRuntimeWorkerOrGuestCode`](../cmd/agentcapsule-api/imports_test.go) (unit, `go list -deps`): `agentcapsule-api` links neither the runtime, nor the worker, nor the volume code, nor any code of the guest programs; [`TestHTTPAgentReservationsAndOwnerIsolation`](../internal/api/agents_test.go) (PG): `host_id` and `volume_path` refused; [`TestOpenAPIDescribesExactlyTheServedRoutes`](../internal/api/openapi_test.go), [`TestRBACMatrixCoversEveryRoute`](../internal/api/rbac_matrix_test.go) (unit): a closed list of routes | — |

## The MVP outcome as one scenario

The outcome sentence of §1, clause by clause, in order. Each step names the
tests and campaigns that together show it.

| ID | Clause | Status | Proof | Missing |
|---|---|---|---|---|
| OUT-1 | On one KVM-capable host | partial | [verify-install.py](../scripts/verify-install.py) (script): the binaries installed from scratch, the worker's preflight passing every check on this machine with the artifacts; [`TestMandatoryOnAGoodFakeHost`](../internal/preflight/preflight_test.go) (unit) | Only one host, under WSL2, has been used. No production host; the preflight never ran as root |
| OUT-2 | An administrator imports several harnesses (Go plus Python or TypeScript) | met | [`TestProductWorkerTenantRunsAnImportedHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): Go, through `POST /v1/harness-imports`; [`TestProductWorkerTenantRunsAPythonHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): Python; [`TestProductWorkerTenantRunsPiOnARealModel`](../internal/worker/product_adapter_integration_test.go) (KVM 2026-11-13): Pi on Node.js | Each test has its own lab: no single run imports both. The registry is in-process over plain HTTP, and the test runs the import itself |
| OUT-3 | Creates isolated agents for two organizations | met | [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go) (KVM 2026-11-15): organizations created by `POST /v1/organizations`, separate VMs, users, volumes and keys; [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) (PG) | The trusts are written to the store, not by `configure-delegation`; [verify-install.py](../scripts/verify-install.py) covers that step without VMs |
| OUT-4 | Uses them over HTTPS | needs KVM | [`TestAPIBinariesBootstrapServeAndShutdown`](../internal/api/server_test.go) (PG); [`TestServerCertificateServesTLSAndReloads`](../internal/operatorconfig/transport_test.go) (unit); [verify-failover.py](../scripts/verify-failover.py) and [verify-install.py](../scripts/verify-install.py) (script): the API binary over HTTPS; the KVM product labs now serve the API over TLS (`httptest.NewTLSServer`) | The KVM runs so far drove the VMs over plain HTTP; the next run is the first over TLS. The labs use Go's test TLS server, not the API binary's |
| OUT-5 | Stops and wakes them without data loss | met | [`TestProductWorkerProvisioningAndEncryptedWake`](../internal/worker/product_provisioning_integration_test.go) (KVM 2026-11-15): clean and forced stops; [`TestProductWorkerTenantRunsAPythonHarness`](../internal/worker/product_registry_integration_test.go) (KVM 2026-11-15): state kept across sleep and wake | — (over plain HTTP, see OUT-4) |
| OUT-6 | A discovers B and gets its answer over A2A/SLIM although B was stopped, on pinned versions | met | [`TestProductWorkerTenantFlagshipJourney`](../internal/worker/product_flagship_integration_test.go) (KVM 2026-11-15): B asleep, found by skill, its answer across a real bridge and the private SLIM node, also with the Directory then SLIM down; [`TestProductWorkerTenantAgentsTalkOverSLIM`](../internal/worker/product_slim_integration_test.go) (KVM 2026-11-15); [verify-interop.py](../scripts/verify-interop.py) (interop): the pinned profile | — (the test runs the Directory publisher and restarts the bridge itself) |
| OUT-7 | Restores agents from an external backup | partial | [`TestProductWorkerRestoresAgentFromArchive`](../internal/worker/product_restore_integration_test.go) (KVM 2026-11-15): a restore from an archive into a new incarnation; [verify-archive-shipping.py](../scripts/verify-archive-shipping.py) (script): archives shipped to S3 and SFTP and fetched back from each alone; [verify-backups.py](../scripts/verify-backups.py) (script): PostgreSQL restored from each store; [`TestRestoreHostMovesTheLostHostsAgentsHere`](../internal/worker/host_restore_test.go) (PG, fake host) and `TestRestoreFromShippedCopies` with `verify-archive-shipping.py --restore-from-copies` (script): a lost host's agent restored on another host from the stores' copies (ADR 020) | The KVM restore uses a local archive on the same host, called in-process. [`TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost`](../internal/worker/product_host_restore_integration_test.go) (KVM: archive, ship, fetch, restore on another worker host) has never run. The chain was never run end to end with PostgreSQL restored and the worker binary |

**The missing links**, in the order of the scenario:
1. One host run from the install to the agents: the worker started as root
   from the install of `verify-install.py`, then the API over HTTPS driving
   VMs.
2. A KVM run of the labs over TLS (changed here), and at best the API binary
   with its certificate, as `verify-failover.py` does.
3. Go and Python harnesses imported in one run, from an HTTPS registry.
4. The restore from the external copy: archive, ship, fetch, restore with
   `-restore-agent`, and on the standby with `-restore-host` (ADR 020).

## Deployment and operations

The promises of §2 and §3.

| ID | Promise | Status | Proof | Missing |
|---|---|---|---|---|
| DEP-1 | Self-hosted, no external telemetry without consent | not met | — | No test denies egress during a run. By design, metrics are served on loopback and nothing calls out |
| DEP-2 | Single host; off-host backups mandatory | partial | [verify-backups.py](../scripts/verify-backups.py), [verify-archive-shipping.py](../scripts/verify-archive-shipping.py) (script) | Nothing makes off-host backups mandatory: the worker's `archives` section is optional, and the PostgreSQL backup and the shipping of archives are separate units that nothing checks are installed. Question for the product owner: a host runs with no off-host backup set up; should (a) the worker refuse to start in production, (b) the platform start and raise an alert until a backup has left the host, or (c) the install guide alone ask for it, as today? Recommended: (b) now, (a) once the install sets up a store by default |
| DEP-3 | KVM required; a preflight refuses an incompatible host | partial | [`TestMandatoryChecksTheRuntimeDisk`](../internal/preflight/preflight_test.go), [`TestTheWorkerChecksItsRuntimeDiskAtEveryStart`](../internal/worker/preflight_test.go) (unit): the worker refuses to start on a runtime disk 95% used or more, warns from 80%, and `-preflight` fails from 80%; [`TestKVMDevice`](../internal/preflight/preflight_test.go), [`TestCgroups`](../internal/preflight/preflight_test.go), [`TestRuntimeFileSystemAndDisk`](../internal/preflight/preflight_test.go) (unit); [verify-install.py](../scripts/verify-install.py) (script): the preflight on this machine, and the refusal | "network" is only network namespaces; the jailer's permissions are not checked beyond root and `/dev/kvm`; no production host. The 95% level at start is a default pending the product owner |
| DEP-4 | An HTTPS API and an administration and diagnostic CLI | met | [verify-install.py](../scripts/verify-install.py) (script): the admin CLI and the API over HTTPS; [`TestAdminRefusesAClearTextDatabaseInProduction`](../cmd/agentcapsule-admin/main_test.go) (unit); [`TestDiagnosticsLeakNoSecretContentOrPersonalData`](../cmd/agentcapsule-admin/diagnostics_test.go) (PG): `agentcapsule-admin diagnostics` exports the host's state, and no secret, content or personal data | — |
| DEP-5 | Capacity starting points, to be measured | not met | — | No run with several VMs, no RAM or boot time committed (OPS-03) |
| OPR-1 | Health and readiness endpoints | met | [`TestAPIBinariesBootstrapServeAndShutdown`](../internal/api/server_test.go) (PG); [verify-install.py](../scripts/verify-install.py), [verify-failover.py](../scripts/verify-failover.py) (script) | — |
| OPR-2 | Prometheus metrics, correlation IDs | met | [`TestHTTPTelemetry`](../internal/api/telemetry_test.go), [`TestHTTPOperationsRecordTheirRequestID`](../internal/api/telemetry_test.go) (PG); [`TestRetryReasons`](../internal/worker/telemetry_test.go) (PG); [`TestProductWorkerTenantAgentsTalkOverA2A`](../internal/worker/product_adapter_integration_test.go) (KVM 2026-11-15): the worker's metrics | — |
| OPR-3 | Traces with pseudonymized IDs | not met | — | No spans (OPS-02) |
| OPR-4 | Redacted logs | met | [`TestFreeTextNeverReachesMetricsOrLogs`](../internal/telemetry/telemetry_test.go) (unit); [`TestAPIBinariesBootstrapServeAndShutdown`](../internal/api/server_test.go) (PG) | — |
| OPR-5 | Operator CLI for queues, boot errors, diagnostics, restore tests, GC | partial | [`TestDiagnosticsLeakNoSecretContentOrPersonalData`](../cmd/agentcapsule-admin/diagnostics_test.go) (PG): the diagnostic export, with each host's queue and the failed boots of 7 days; [`TestReplayDeadLetterCommand`](../cmd/agentcapsule-admin/replay_test.go) (unit), [`TestTheOperatorReplaysADeadLetter`](../internal/controlplane/instruction_replays_test.go) (PG): dead letters; [`TestDestructiveCommandsAreConfirmedDryRunAndAudited`](../cmd/agentcapsule-admin/guard_test.go) (PG) | No command tests a restore or collects garbage: the restore is the worker's `-restore-agent`, and archives and cached images are cleaned up automatically. Boot failures have `clear-agent-failure`, without a test of the command itself |
| OPR-6 | Disk alerts at 70% and 80% | met | [verify-alerts.py](../scripts/verify-alerts.py) (script): `AgentCapsuleDiskPressure` and `AgentCapsuleDiskCritical` with promtool tests; [`TestRuntimeFileSystemAndDisk`](../internal/preflight/preflight_test.go) (unit) | — |
| OPR-7 | Imports and new volumes refused past a pressure threshold | met | [`TestStoragePressureIsRecordedAndServed`](../internal/worker/operations_test.go) (PG): a file system past its threshold is recorded; [`TestStoragePressureRefusesNewVolumesAndImports`](../internal/controlplane/operations_test.go) (PG): new agents and imports refused while it lasts, nothing reserved; [`TestHTTPStoragePressureIsATypedRefusal`](../internal/api/operations_test.go) (PG): `storage_pressure`; [`TestImportsWaitUnderStoragePressure`](../internal/worker/operations_test.go) (PG): an import downloads nothing | — |
| OPR-8 | Alerts on CPU, memory, queue age, boot failures, Directory or SLIM outages | met | [verify-alerts.py](../scripts/verify-alerts.py) (script): promtool tests of `AgentCapsuleHostCPUSaturated`, `AgentCapsuleHostMemoryLow`, `AgentCapsuleQueueDelayed`, `AgentCapsuleInvocationsDelayed`, `AgentCapsuleVMBootFailures`, `AgentCapsuleDirectoryUnavailable` and `AgentCapsuleSLIMUnavailable`, each firing and staying silent; the script fails on a rule without both cases; [`test_the_repository_rules_are_all_tested`](../scripts/test_verify_alerts.py) (unit) | — |
| OPR-9 | Off-host, encrypted, versioned backups of PostgreSQL and volumes | met | [verify-backups.py](../scripts/verify-backups.py), [verify-archive-shipping.py](../scripts/verify-archive-shipping.py) (script): both stores, no clear text, restore from each; [`test_fetch_from_each_store`](../scripts/test_archive_ship.py) (unit) | — (the provider's versioning and object lock are not qualified) |
| OPR-10 | Backups of harness digests | needs KVM | [`TestRefillFetchesAgainThePackagesThisHostsAgentsPin`](../internal/worker/registry_test.go) (PG): a lost cache is filled again from the digests PostgreSQL keeps, with only the packages the host's agents pin, each verified against its release's root file system; [`TestProductWorkerRefetchesTheHarnessOfARestoredAgent`](../internal/worker/product_refill_integration_test.go) (KVM, never run): with the cache lost, the package is fetched again by digest, and the agent, restored from its archive, boots it and answers; the digests are in the PostgreSQL backup ([verify-backups.py](../scripts/verify-backups.py)) | The KVM test has never run. A one-shot `-restore-agent` or `-restore-host` does not fetch packages: the worker service does, once a minute. A package that its registry no longer serves cannot be fetched again |
| OPR-11 | Consistent backups (quiesce first), with freshness alerts | met | [`TestProductWorkerNightlyVolumeArchives`](../internal/worker/product_archives_integration_test.go) (KVM 2026-11-15): archives of sleeping or stopped agents; [`TestArchiveSettleAndRetention`](../internal/worker/archive_schedule_test.go) (PG); [verify-alerts.py](../scripts/verify-alerts.py) (script): freshness alerts with promtool tests | — |
| OPR-12 | Restore tested on another KVM host | not met | [`TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost`](../internal/worker/product_host_restore_integration_test.go) (KVM, never run): a second worker host, one machine | The KVM run, then a run between two real hosts |
| OPR-13 | RPO and RTO documented and measured | partial | [verify-failover.py](../scripts/verify-failover.py) (script): the database, the authorities, their reconciliation and the API, on one machine, scaled settings, and the takeover of the lost host; the API refuses to open before the reconciliation; the agents' time budget in [ADR 020](adr/020-restoring-a-lost-hosts-agents.md#the-procedure-and-its-time) | The agents and the worker, between real hosts |
| OPR-14 | A lost invocation shown as `lost` and run again | met | [`TestProductWorkerRestoresAgentFromArchive`](../internal/worker/product_restore_integration_test.go) (KVM 2026-11-15); [`TestRestoreQueuesTheRerunOfLostInvocations`](../internal/controlplane/invocation_reruns_test.go), [`TestRerunsCommitWithTheRestoreAndSurviveCrashes`](../internal/controlplane/invocation_reruns_test.go) (PG); [`TestRevokedRequesterLostInvocationIsNeverRerun`](../internal/controlplane/invocation_reruns_test.go) (PG) | — (after a restore on the same host) |
| OPR-15 | Lost requests between agents delivered again | needs KVM | [`TestRestoreRedeliversALostRequest`](../internal/controlplane/peer_redeliveries_test.go), [`TestRestoreDoesNotReopenAFinalRequest`](../internal/controlplane/peer_redeliveries_test.go), [`TestRestoreRedeliversALostReplyAndStatus`](../internal/controlplane/peer_redeliveries_test.go) (PG); [`TestProductWorkerRestoresAgentToAgentExchange`](../internal/worker/product_restore_integration_test.go) (KVM, never run) | The KVM test has never run |
| OPR-16 | A restore never revives revoked memberships, assignments, tokens, delegations or keys | partial | [`TestOldImageDoesNotReviveDestroyedKey`](../internal/restoreauthority/key_runs_test.go), [`TestRevocationSurvivesRestoredKeyAndPrecedesCreation`](../internal/keyauthority/files_test.go) (unit): keys; [`TestRevokedRequesterLostInvocationIsNeverRerun`](../internal/controlplane/invocation_reruns_test.go) (PG); [`TestGrantRevocationResumesAfterResync`](../internal/api/revocation_runs_test.go) (PG, real authority service), [`TestAccessRecordReachesTheReplicaAndSurvivesThePromotion`](../internal/restoreauthority/access_test.go) (unit): each access revocation is recorded with the authorities before its commit, reaches the standby and survives its promotion (ADR 006 wave 5); [`TestReconciliationReplaysRoot`](../internal/api/reconciliation_runs_test.go), [`TestReconciliationReplaysEveryRevokingRoute`](../internal/api/reconciliation_kinds_test.go), [`TestShippedGrantRevocationSurvives`](../internal/api/reconciliation_runs_test.go), [`TestTokenRevocationCoveredByBlanket`](../internal/api/reconciliation_runs_test.go), [`TestEarlyOpenGuard`](../internal/api/reconciliation_runs_test.go) (PG, real authority service and its promotion): the reconciliation replays every revocation the promoted database lacks, keeps the database's own in the authorities, revokes every bearer token issued before a failover that may have ended a degraded period, and the API opens only after it (ADR 006 wave 7) | A revocation of a release before ADR 006 wave 5, or of development mode, has no record. A database restored in place, at the same epoch, is not detected: the API opens on it unless the operator runs `reconcile` first, by hand (recovery.md); the replay itself is the one `TestReconciliationReplaysEveryRevokingRoute` proves. Checked on 2026-11-16: neither gap can be closed by a test alone; detecting an in-place restore is a change of ADR 006 (a revocation recorded by the authorities whose commit failed looks the same as one a restore lost) |
| OPR-17 | Revocation: no later call succeeds | met | [`TestHTTPMembersIdempotencyAndRevocation`](../internal/api/members_test.go), [`TestMembersRevocationWaitsForAdmissionAndRefusesStaleReplay`](../internal/controlplane/members_test.go) (PG); [`TestDelegationRotationCannotResurrectRevokedToken`](../internal/controlplane/tenant_identity_test.go) (PG); [`TestTenantResultBelongsToTheRequesterAndCurrentRights`](../internal/controlplane/tenant_invocation_test.go) (PG) | — |
| OPR-18 | Deletion blocks work, stops the VM, destroys volume, key and Directory record | needs KVM | [`TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord`](../internal/worker/product_deletion_integration_test.go) (KVM with the private services, never run): queued work canceled and new work refused once the deletion is accepted, then no VM, no volume, the key revoked and destroyed through the authority service under the seal it checks, and the Directory record withdrawn; [`TestProductWorkerTwoOwnersPrivateExchange`](../internal/worker/product_peers_integration_test.go) (KVM 2026-11-15): VM, volume and key; [`TestDestructionRequiresPermanentSeal`](../internal/authorityclient/key_runs_test.go) (unit): the key is destroyed only once its store is sealed, through the service and in process; [`TestDeletedAgentArchivesArePurged`](../internal/worker/archive_purge_test.go) (PG): the host's archives go once the key is destroyed; [verify-archive-shipping.py](../scripts/verify-archive-shipping.py) (script): the stores' copies expire by age; [`TestPublisherFollowsTheAgentsRevisions`](../internal/directory/publisher_test.go) (unit): the record withdrawn | The test has never run; it needs `--slim-bridge-build` |

## Release validation

### Install from scratch

[verify-install.py](../scripts/verify-install.py) starts from an empty
directory, builds every binary and installs them into a throwaway prefix.
Then it follows [bootstrap.md](bootstrap.md) and [install.md](install.md)
without root:
- PostgreSQL;
- the migration;
- the platform credential;
- the API over HTTPS with a CA of its own, after its preflight;
- an organization and its trust;
- the owner signing in and naming an administrator;
- the audit;
- the authority service, standalone;
- the worker's preflight.

It ends with a call by the organization's owner. It runs in CI (job
`install`) in about a minute after the build. Its unit tests are
[`test_kvm_reported_fine_when_the_account_cannot_open_it_fails`](../scripts/test_verify_install.py) and the
others of [test_verify_install.py](../scripts/test_verify_install.py).

It does not install:
- the Directory and the SLIM node (Docker);
- the replica of the authorities;
- the systemd units;
- the transit keys and the host's capacity, which the first agent needs.

It does not start the worker as root, so no VM runs.

### Version matrix

What exists:
- the interoperability profile, pinned and checked by `verify-interop.py`
  ([profile.json](../runtime/interop/profile.json)): A2A 1.0.1 with a2a-go
  2.8.0; OASF 1.1.0; Directory 1.8.0; SLIM 3.4.6;
- Firecracker 1.17.0 ([manifest.json](../runtime/firecracker/manifest.json));
- the guest kernel 6.1.188 ([kernel.json](../runtime/guest/kernel.json));
- pgBackRest 2.58 and rclone 1.60.1;
- PostgreSQL 16 in CI, from Ubuntu 24.04 and not pinned; 18 in the local
  campaigns;
- Go 1.27.3 in CI. `go.mod` states 1.27.2 as its minimum.

What the MVP still needs:
- one table of the tested versions, kept by a check;
- CI on PostgreSQL 16 and 18;
- a host kernel other than WSL2's: 6.1 or 6.18 on a real server;
- one Go version stated for releases (VAL-03 plans 1.27.4).

### Chaos tests

What exists:
- process kills: [`TestAPIProcessCrash`](../internal/controlplane/store_test.go), [`TestDeliveryWorkerProcessCrash`](../internal/controlplane/delivery_test.go),
  [`TestReplyAPIProcessCrash`](../internal/controlplane/replies_test.go), [`TestAbortedWriterThenFence`](../internal/controlplane/model_runs_test.go),
  [`TestKeyAuthorityProcessCrashRecovery`](../internal/keyauthority/files_test.go), [`TestPrimarySIGKILLBetweenCommitAndAcknowledgment`](../internal/restoreauthority/replication_crash_test.go),
  [`TestReplicaSIGKILLMidApply`](../internal/restoreauthority/replication_crash_test.go),
  the API process right after its 202 in [`TestAPIKilledAfterAcceptanceLosesNoInvocation`](../internal/api/acceptance_crash_test.go);
- PostgreSQL crash and WAL recovery: the recovery phase of
  [verify-postgres.py](../scripts/verify-postgres.py), an accepted invocation
  included ([`TestInvocationDatabaseRecovery`](../internal/controlplane/invocation_recovery_test.go));
- worker and VMM crashes on KVM (2026-11-09): [`TestFirecrackerWorkerCrash`](../internal/runtime/firecracker_integration_test.go),
  [`TestPostgresKVMWorkerCrashAfterDatabaseConfirmation`](../internal/worker/placements_integration_test.go),
  [`TestDispatchWorkerCrashRecovery`](../internal/worker/dispatch_integration_test.go), [`TestPlatformListenerOwnerSIGKILL`](../internal/worker/platform_integration_test.go);
- outages of the services:
  - the Directory and SLIM in [`TestProductWorkerTenantFlagshipJourney`](../internal/worker/product_flagship_integration_test.go);
  - the authority service in [`TestWorkerKeepsItsVMsWhileTheServiceIsDown`](../internal/worker/authority_test.go);
  - the SLIM node in [`TestABridgeEndsWhenTheNodeIsLostAndANewOneWorks`](../runtime/slimbridge/services_test.go);
- a killed upload and a network cut in
  [verify-archive-shipping.py](../scripts/verify-archive-shipping.py);
- the loss of the primary in [verify-failover.py](../scripts/verify-failover.py).

What the MVP still needs:
- network partitions: worker to PostgreSQL, worker to SLIM and the
  Directory, API to PostgreSQL;
- a full disk;
- power loss in the durability runs (VAL-01);
- crashes under load;
- the failover of agents between two real hosts.

### Isolation tests

What exists:
- between VMs and the host: [verify-vm-isolation.py](../scripts/verify-vm-isolation.py)
  (KVM, its own jailer lab: UIDs, capabilities, seccomp, cgroups, another
  VM's volume, vsock and signals refused), and
  [`TestProductGuestEncryptedPersistenceAndIsolation`](../internal/runtime/product_guest_integration_test.go);
- between organizations: [`TestProductWorkerTwoOrganizationsStayIsolated`](../internal/worker/product_organizations_integration_test.go),
  [`TestRBACMatrix`](../internal/api/rbac_matrix_test.go) and the rows ISO-1 to ISO-7.

What the MVP still needs:
- a cross-organization attempt between agents over A2A and SLIM, from VMs;
- the isolation runs on the product runtime and on a real host;
- noisy neighbours: one agent's load against another's latency (RUN-007);
- the statistics of ISO-6 for the queues and the model usage.

### Load tests and benchmarks

What exists:
- the load test [`TestLoad`](../internal/worker/load_test.go), driven by
  `scripts/load-test.py` (PG, no VM): on 2026-11-16, on the development
  machine, the API admitted up to 80 invocations a second with a p99 below
  130 ms, and one dispatch loop delivered 8 a second
  ([worker.md](worker.md#load-test));
- no `Benchmark` or `Fuzz` function;
- capacity tests with one slot, for correctness only:
  [`TestDispatchPreparationAndOneSlotCapacity`](../internal/worker/dispatch_integration_test.go),
  [`TestBarrierCapacityOneSlotThreeStoresAndReplay`](../internal/worker/capacity_integration_test.go);
- concurrency tests: [`TestConcurrentReservationsNeverOvershootAHardBudget`](../internal/controlplane/llm_budgets_test.go),
  [`TestHTTPConcurrentCreationHasOneDurableOperation`](../internal/api/agents_test.go);
- measures written in the docs: the RTO and RPO of the failover, and the
  footprint of the interoperability services.

What the MVP still needs (OPS-03; load tests may come from the operations
work):
- a run at `max_active` with N VMs: RAM per VM, boot time p50 and p95;
- the load test on a production host;
- the scheduler at capacity with real VMs.

### KVM runs the MVP still needs

- Never run: [`TestProductWorkerDriveCeilingsHoldAgainstAFloodingGuest`](../internal/worker/product_limits_integration_test.go)
  (RUN-007), [`TestProductWorkerStopsBootingAGuestThatCrashesAtBoot`](../internal/worker/product_limits_integration_test.go)
  (RUN-011), [`TestProductWorkerRestoresAgentToAgentExchange`](../internal/worker/product_restore_integration_test.go) (OPR-15),
  [`TestProductWorkerBoundsTheGuestTmp`](../internal/worker/product_content_integration_test.go),
  [`TestProductWorkerDeliversJSONContent`](../internal/worker/product_content_integration_test.go) (EXT-001) and
  [`TestProductWorkerEnforcesCapabilities`](../internal/worker/product_content_integration_test.go) (EXT-003, LLM-004),
  [`TestProductWorkerJailsEachVMAndLeavesNothingBehind`](../internal/worker/product_jail_integration_test.go) (RUN-002, RUN-008),
  [`TestProductWorkerWakesQueuesAndKeepsAWorkingAgentAwake`](../internal/worker/product_idle_integration_test.go) (EVT-002, EVT-010),
  [`TestProductWorkerSenderWakesForTheReply`](../internal/worker/product_replies_integration_test.go) (A2A-010) and
  [`TestProductWorkerRefetchesTheHarnessOfARestoredAgent`](../internal/worker/product_refill_integration_test.go) (OPR-10).
  `verify-product-guest.py` requires every one of them.
- With `--slim-bridge-build`, never run:
  [`TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord`](../internal/worker/product_deletion_integration_test.go)
  (OPR-18), and the check of the SLIM node's log in
  [`TestProductWorkerTenantAgentsTalkOverSLIM`](../internal/worker/product_slim_integration_test.go) (A2A-005).
- Every product test, again, with the integrated guest: the code changed
  after the run of 2026-11-15, and the labs now serve the API over TLS
  (OUT-4).
- The control and runtime tests of `verify-runtime.py`: last run
  2026-11-09.
- The worker started by its unit from the install of `verify-install.py`,
  as root (OPS-01).

## Findings

Inconsistencies found while tracing, with where they are. None is fixed here
unless said.

- **product.md against the code:**
  - `BUSY` (§3, EVT-002) is not a state of the code; `QUEUED` (RUN-011) is
    since ADR 017;
  - RUN-001 says "without booting", but creation boots a restricted VM to
    format the volume;
  - REG-001 and the API conventions promise `operation_id`, but invocations,
    their replay and harness imports answer with `id`;
  - EVT-009 says `GET /v1/operations/{id}` gives the result; it is at
    `/result`;
  - A2A-008 lists "delivered" and "working" apart; the code has one state,
    `PROCESSING`;
  - §3 says the gateway enforces `llm.invoke`: the host's platform channel
    enforces it since ADR 016, before the gateway;
  - §2 has the preflight refuse an incompatible host, disk included, while
    ADR 010 kept the disk out of the start so that a disk at 81% does not
    stop running agents. The start now refuses a runtime disk from 95%
    (DEP-3), a default pending the product owner;
  - §3 promises backups of harness digests (OPR-10), but nothing could fetch
    a package again: a new import of a known digest answers with the old
    import. The worker now fetches the packages its agents pin when its cache
    lacks them.
- **Idempotency keys, two scopes:** a key reused on another target of the
  same route gets `422` on most routes, and runs as a new request where the
  receipt's scope holds the target (organization disable, release
  deprecation, agent deletion, wake, sleep, invocation cancel and replay,
  held request decisions, attachment deletion). Neither gives back the first
  target's answer ([`TestEveryMutationNeedsAnIdempotencyKey`](../internal/api/conventions_test.go)).
- **Fixed since** (the cleanup of the integration):
  - docs/interop.md said the search filters by assignment; it filters by
    organization and discoverability;
  - docs/recovery.md said nothing copies the keys, that the nightly archives
    and the promotion were still to come, and listed the redelivery between
    agents as to do;
  - docs/worker.md said the deletion in a real VM remained to run under KVM;
  - the audit check of [`TestLLMProviderSecretsStayWriteOnlyAndEncrypted`](../internal/controlplane/llm_providers_test.go)
    never asserted; it now requires the creation's audit row;
  - `verify-product-guest.py` did not require the newest worker tests; it
    now refuses a product worker test it does not list;
  - [`TestAuditFeedIsCompletePagedAndMetadataOnly`](../internal/controlplane/audit_feed_test.go) has no content check:
    [`TestAuditTrailHoldsNoConversationContent`](../internal/controlplane/audit_content_test.go) now makes it.
- **Tests weaker than their names:**
  - [`TestQueueTenantLimitSpansAgentsAndIsolatesTenants`](../internal/controlplane/instruction_queues_test.go) uses one
    organization.
- **The install from scratch** (fixed in the docs here):
  - bootstrap.md did not say that the build needs a C compiler and
    libcryptsetup's headers;
  - it did not say that the API's `-host-id` is the worker's `host_id`;
  - it did not say that a refused `bootstrap-platform` still writes its new
    token file;
  - it did not say what the first agent needs after step 6;
  - install.md's operator steps had no migration, platform credential or
    authority service before the preflight.
