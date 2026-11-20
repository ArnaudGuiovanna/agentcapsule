# Templates, deployments and pools

The platform operator approves an immutable system image reference. The API serves the intersection of approved references and the digest pairs reported by its configured worker. The worker verifies the kernel and initrd when it starts and stages them by SHA-256. A tenant can select a reference, with no access to paths on the host.

```http
POST /v1/system-images
Authorization: Bearer <platform-token>
Idempotency-Key: image-1
Content-Type: application/json

{"reference":"ubuntu@1","kernel_digest":"sha256:<64 hex>","initrd_digest":"sha256:<64 hex>"}
```

`features` (default none) lists what the image's `capsule-init` can do beyond
the base guest, from a closed list: `corpus.mount`, it mounts corpora
([ADR 023](../adr/023-corpora.md) §5.5). An approval is immutable: the same
reference approved again with other digests or other features is
`409 invalid_transition`. `GET /v1/system-images` shows each image's
`features`.

The worker reports its default kernel and initrd automatically. Additional pairs belong in its configuration under `system_images`, each with `kernel` and `initrd` image objects using the same path and SHA-256 fields as the default image. For an imported OCI harness, the verified root filesystem is a separate read-only drive. An image with a built-in harness must have the same initrd digest as the local harness release.

With an organization owner's session, send each POST with its own Idempotency-Key.

| Method and resource | Example JSON body | Result |
|---|---|---|
| POST /v1/templates | `{"name":"support","system_image":"ubuntu@1","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":64},"capabilities":["llm.invoke"]}` | Immutable reference such as `support@1` |
| POST /v1/deployment-plans | `{"template":"support@1","count":100,"active_count":5}` | Plan ID, per-resource demand and availability, worker observation time |
| POST /v1/deployment-plans/{id}/apply | `{}` | HTTP 202 and the deployment ID |
| GET /v1/deployments/{id} | | Counts of provisioned volumes, pending enrollments, capacity waits, active application VMs and failures |
| POST /v1/pools | `{"name":"personal","deployment_id":"dep_…"}` | Pool ID and its inventory |
| GET /v1/pools/{id} | | Total agents, unassigned live agents and unassigned enrollments in progress |

Publishing an optional `llm_profile` grants agents the named model alias and requires `provider:manage`. The organization and harness capability ceilings still apply. Set `capabilities` to an empty array to allow no platform capabilities. A deployment can override its revision's entire `resources` object.

Configure `provisioning.deployment_memory_mib` and `provisioning.deployment_vcpus` as the budgets available to VMs after accounting for local inference, PostgreSQL and host services. Defaults are the host's available memory (Linux MemAvailable) at worker startup and its available CPUs. VM calculations include 256 MiB per active VMM, matching the runtime cgroup limit. Initializing a cold volume still needs one boot slot. A full host leaves a template agent's initialization queued until a slot opens. The worker's existing dispatch batch governs jobs per pass.

Applying takes the organization's and host's reservation locks and rechecks quotas, storage, UID space and requested warm capacity. One transaction records every agent, volume identity and provisioning operation. Reapplying the same plan after loss of the HTTP receipt follows the original deployment. Physical work resumes from durable enrollment records. A different template revision gets a different plan. Agents created later by a pool expansion appear in pool inventory separately from the original deployment's requested count.

Set `count` to the total number of agents and `active_count` to the number to keep ready for requests. The worker fills a shortfall from enrolled members after ordinary jobs, when the host and organization have room. An application VM started for a request counts toward the target. Additional requests can bring more members online. After a VM exits or is evicted, the worker retries on later passes without a client wake. A requested sleep or an idle-policy sleep removes that member from automatic replenishment until its next explicit wake. Application requests can still start it. The worker can select a different member. Open rollouts, enrollment work and capacity waits can delay replenishment. `GET /v1/deployments/{id}` returns the target in `active_count` and the current authenticated count in `active`.

On WSL2 with PostgreSQL 18.6, `TestDeploymentBatchSizesAndQuotaBoundaries` admitted successive batches of 1, 50, 100 and 1,000 agents. After each batch the test expired its HTTP receipt, closed the database connection pool and reapplied the plan through a fresh catalog. Every ordinal retained its original agent, volume and provisioning operation. At the cumulative quota of 1,151 agents, the next reservation returned `max_agents` with zero available. The test checked the final counts of agents, specifications, operations, enrollments and deployment members. `TestDeploymentResumesWithDistinctVolumesAndImmutableTemplate` exercises concurrent apply, restart after partial initialization and a pool expansion.

### Measured deployment on WSL2 with KVM

On 19 November 2026, the Linux worker ran Firecracker on an Intel Core i7-9750H with 12 logical CPUs and 15.5 GiB of memory visible to WSL2. Each agent received its own 128 MiB LUKS volume. The table records individual observations from a run of `TestProductDeploymentCampaignKVM`. “Active in batch” counts application VMs belonging to that deployment at completion. Disk figures include every agent created up to that point.

| Requested | Provisioned | Active in batch | Apply response | Time to ready | Total logical disk | Total allocated disk |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 25 ms | 5.95 s | 128 MiB | 27.33 MiB |
| 3 | 3 | 1 | 22 ms | 25.37 s | 512 MiB | 109.40 MiB |

During the three-agent batch, the test restarted the worker after it initialized the first volume. An already active agent from the preceding batch answered a request in 22.34 s across that interruption. Once provisioning finished, the warm agent in the new batch returned its first response in 452 ms. The test checked four distinct volume inodes and their LUKS headers. These timings represent single requests. The larger batches above were exercised in PostgreSQL.

The same KVM run exercised the quota boundary and a template rollout. The API refused the fifth reservation. After the competing VM released its slot, the worker started the rollout on the three-agent batch. The failed canary paused the update. Once the artifact was repaired and the rollout resumed, all three agents completed an authenticated boot on `support@2`.

On 20 November 2026, a second WSL2 KVM run exercised recovery of the requested active count. After the host retired the active member’s VM, the worker restored the target of one with boot generation 3 following generation 2. An explicit sleep then left that member stopped and the worker started a different member from the same deployment. After the rollout canary paused and resumed, all three members authenticated on `support@2`. The test read 2 vCPUs and 384 MiB from the running Firecracker machine configuration, up from 1 vCPU and 256 MiB. The full test took 60.46 s. In this run and a repeat with the same binary, the three-agent batch completed in 27.92 s and 16.95 s (0.107 and 0.177 provisioned agents/s). The active neighbor answered in 27.71 s and 16.88 s across the worker interruption. The warm member answered its first request after provisioning in 486 ms and 280 ms. The cumulative volumes occupied 109.40 MiB in both runs. These runs recorded allocated blocks. Disk throughput, I/O wait and device saturation during those windows remain unmeasured. [KVM test](../../internal/worker/product_deployments_integration_test.go)

The KVM test now samples Linux I/O counters before each deployment plan and when the batch reports ready. It logs UTC boundaries, elapsed seconds and cumulative samples plus deltas. The block counters cover all users of the volume filesystem’s device. They count completed reads and writes, transferred bytes, read and write milliseconds, busy milliseconds and weighted I/O milliseconds. The kernel’s I/O pressure counters cover the whole host. `some_us` measures microseconds with at least one task stalled on I/O and `full_us` measures microseconds with all non-idle tasks stalled on I/O. Empty fields indicate unavailable counters. Other processes and device caching can affect the observations. A block-transfer rate in bytes/s is the corresponding byte delta divided by the recorded elapsed seconds.

On 20 November 2026, the same KVM campaign ran under WSL2 with PostgreSQL 18.6. The volume filesystem used device 8:48. One agent became ready in 5.42 s. Device counters recorded 5.87 MB read and 171.16 MB written, with 9.74% busy time. Host I/O pressure reported 0.84% `some` and 0.66% `full` stalls during that interval. Three agents became ready in 19.66 s. The device recorded 13.15 MB read and 559.59 MB written, with 9.13% busy time. Host pressure reported 0.76% `some` and 0.61% `full` stalls. One active neighbor answered an invocation during the three-agent batch in 322.7 ms. These counters include other traffic on device 8:48 and pressure from the whole host. The campaign passed, including active-member replacement, authenticated rollout boots and resize to 2 vCPUs and 384 MiB. [Raw WSL report](../../_evidence/cli-provisioning-io/report-20261120.json)

## Resizing one agent

Send `POST /v1/agents/{id}/resize` with `{"vcpus":2,"memory_mib":512}` and an `Idempotency-Key`, or run `agentcapsule agent resize AGENT --vcpus 2 --memory-mib 512`. Supply both target values. An enrolled tenant agent may have been created individually or from a deployment. Its deployment membership, template, encrypted volume, system image, harness, capability policy and LLM grants are preserved.

The response identifies a one-member rollout with the requested resources. Inspect it with `rollout show ID` and `rollout members ID`. The current profile remains visible on `agent show AGENT` until installation. The worker waits for acknowledged work to finish, records whether the agent was running, performs a controlled stop and validates the new configuration with an authenticated boot. A previously stopped agent sleeps again after validation. An individually unbootable profile is refused during admission. A pending increase on a warm member counts toward new deployment admissions. The validation boot waits with reason `waiting_capacity` if the concurrent guests would exceed the host CPU or memory budget or the organization quota. The worker retries each eligible rollout and preserves the other placements. A paused rollout can be resumed with `rollout resume ID`. A conflicting rollout, a volume growth in progress or an unchanged profile returns HTTP 409.

## Updating a deployed template

Publish a revision, then send `POST /v1/deployments/{id}/rollouts` with `{"template":"support@2","max_unavailable":2}`. Poll `GET /v1/rollouts/{id}`. The worker preloads the approved OCI digest on its host. The first wave contains one canary and each later wave is bounded by `max_unavailable`. A worker processes one member per dispatch pass. It waits for acknowledged work, records maintenance durably, stops the VM, and installs the requested system image, harness, CPU and memory. Every member proves the new configuration with an authenticated application boot. Agents that were stopped are stopped again after this check.

The response reports the requested template, the number of authenticated boots on that template, completed members and members in maintenance. When a validation boot awaits a free slot or an organization allowance, the campaign stays running with reason `waiting_capacity` and retries on subsequent worker passes. A failed canary pauses progression. Restore the missing artifact or correct the reported host fault, then send `POST /v1/rollouts/{id}/resume` with `{}`. A retry keeps the same rollout and agent identities. A CPU or memory update retains each original encrypted volume. A disk-size change requires a separate storage operation.

## Grow a private volume

An organization administrator can request a larger size through `POST /v1/agents/{id}/volume-growth` with an idempotency key and a body such as `{"size_mib":192}`. The response gives the growth, archive and restore identifiers. Poll `GET /v1/volume-growth/{id}` for its stage.

The worker requires a configured archive root and a guest supervisor that supports offline expansion. Admission reserves the additional MiB against host and organization storage. The worker checks guest support before changing the volume, waits for in-flight work, stops the VM cleanly and captures an authenticated ciphertext archive. It restores the capture into the registered inode at the new capacity and obtains a new incarnation from the independent restore authority. The restricted guest verifies the LUKS and ext4 identities, expands ext4 offline and checks its integrity. Revocation fences and the outcomes in the installed image are reconciled before the worker publishes success. The agent wakes on its next invocation.

A worker restart resumes the recorded capture or restore using the original identifiers. A worker without a configured archive root reports `archive_unconfigured` for a new request. A supervisor without expansion support produces `refused` with `guest_incompatible` and releases the reservation. The original archive remains usable at its recorded capacity for a later restore into the grown volume.
