# Templates, deployments and pools

The platform operator approves an immutable system image reference. The API serves the intersection of approved references and the digest pairs reported by its configured worker. The worker verifies the kernel and initrd when it starts and stages them by SHA-256. A tenant can select a reference, with no access to paths on the host.

```http
POST /v1/system-images
Authorization: Bearer <platform-token>
Idempotency-Key: image-1
Content-Type: application/json

{"reference":"ubuntu@1","kernel_digest":"sha256:<64 hex>","initrd_digest":"sha256:<64 hex>"}
```

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

The PostgreSQL regression `TestDeploymentBatchSizesAndQuotaBoundaries` exercises batches of 1, 50, 100 and 1,000 and checks every reserved identity. `TestDeploymentResumesWithDistinctVolumesAndImmutableTemplate` exercises concurrent apply, restart after partial initialization and a pool expansion. These counts describe logical reservations and SQL worker observations. KVM timing and physical volume measurements require the deployment host.
