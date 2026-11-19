# Administer AgentCapsule from a terminal

Use the portable `agentcapsule` binary on the administrator's workstation. A platform operator installs the Ubuntu host, enrolls a named operator and gives Acme its initial owner. The owner can then administer Acme over HTTPS. MonApp's backend and each signed-in member use their own API credentials.

| Responsibility | Entry point | Where authorization is checked |
|---|---|---|
| Install, upgrade, inspect host services, archive and restore | `install`, `update`, `host`, `archive`, `restore` | On the Ubuntu host, locally as root or through `--ssh USER@HOST` and noninteractive sudo |
| Enroll an operator, create an organization, set quotas, approve a system image | Platform context over HTTPS | Platform credential and current revocation state |
| Manage Acme, providers, deployments, MonApp and permissions | Organization context over HTTPS | Organization, role, scopes and effective assignments |
| Accept an invitation, invoke an agent, read a result | MonApp's public HTTP contract | Member's verified OIDC identity and current rights |
| Replace the workstation binary | `self update` | Signature, release digest and local filesystem access |

Choose the CLI for your OS and architecture and verify the downloaded binary against the signed checksums. The install guide describes the host profile, offline assets, checkpointed operations, systemd restart and service, invocation and backup checks. [Release verification](release.md#verify-a-release) · [Host installation](cli-host.md)

## Enroll the platform operator and hand Acme to its owner

The host installer writes a single-use, time-limited enrollment file. Transfer it privately to the intended operator and supply the trusted API CA when the installation uses private PKI. Run the following on the operator's workstation. The example uses a separate context for each environment.

```sh
agentcapsule context add platform-dev --url https://agents.acme.example:9443 \
  --kind platform --ca api-ca.pem
agentcapsule --context platform-dev login --enrollment-file first-enrollment.token
agentcapsule --context platform-dev session show
agentcapsule --context platform-dev doctor
```

On the **owner's** workstation, generate a personal Ed25519 key and send the public identity file to the platform operator. The owner retains the private PEM file. The API binds this public key to Acme and checks current membership on every request.

```sh
agentcapsule identity create --key-file owner.pem --display-name "Acme owner" \
  --output-file acme-owner.json
```

On the **operator's** workstation, create Acme and set its quotas. These shell examples use `jq` to read the JSON responses. Persist returned identifiers and reuse the same idempotency key when retrying a mutation.

```sh
org=$(agentcapsule --context platform-dev organization create --name Acme \
  --owner-file acme-owner.json --idempotency-key create-acme | jq -er '.data.id')
agentcapsule --context platform-dev quota set "$org" --file - --idempotency-key quota-acme-1 <<'JSON'
{"max_agents":20,"max_active_vms":3,"max_vcpus":6,"max_memory_mib":2048,"max_storage_mib":4096}
JSON
```

On the owner's workstation set `org` to the returned organization ID, add Acme and log in. A signing-key context mints short-lived proofs as needed. Organization contexts also accept a private access-token file containing an API token with `org:read`. The client verifies its organization before using it.

```sh
agentcapsule context add acme-dev --url https://agents.acme.example:9443 \
  --kind organization --organization "$org" --ca api-ca.pem
agentcapsule context use acme-dev
agentcapsule login --key-file owner.pem
agentcapsule team create --name Support --idempotency-key create-support
```

A platform operator can rotate their session with `session renew` and invalidate it with `logout`. If an exchange response is lost, repeating the command recovers the credential already persisted privately on the workstation. Organization logout clears the local login. Membership and issuer revocation are separate server operations.

## Select inference and provision a pool

1. From the verified release manifest, publish the kernel and initrd pair that the organization will use. The reference in this example is `ubuntu@1`. Check that the worker reports the approved image.

   ```sh
   jq -e '{reference:"ubuntu@1",kernel_digest:("sha256:" + .sha256.vmlinux),initrd_digest:("sha256:" + .sha256["product.initrd"])}' agentcapsule-bundle.json > image.json
   agentcapsule --context platform-dev system-image publish --file image.json
   agentcapsule --context platform-dev system-image list
   ```

   The installed starter harness is named `starter`, version `1.0.0`. Import an additional signed harness with `registry import --reference REGISTRY/REPOSITORY@sha256:DIGEST`, then `operation wait --type harness-import IMPORT_ID`. [Image and template bodies](api/deployments.md) · [Registry](registry.md)
2. Create the provider, alias and budget under Acme. Supply a provider's secret with `--auth-mode secret --secret-file PATH`, or choose `--auth-mode none` for an endpoint that accepts unauthenticated calls. The production worker requires TLS and uses its configured egress allowlist for internal endpoints. [LLM API](api/llm.md) · [Transport and worker policy](install.md#model-providers-on-internal-addresses)
3. Publish a template and apply a capacity plan. The example keeps one VM warm and reserves persistent storage for all three. Save the same plan ID across retries. Inspect the plan's `admitted` flag and per-resource quantities before applying.

```sh
provider=$(agentcapsule provider create --name internal --kind openai_compatible \
  --base-url https://models.acme.example/v1 --auth-mode none | jq -er '.data.id')
agentcapsule alias create --alias support-model --upstream-model acme-support \
  --provider-id "$provider" --file - <<'JSON'
{"access":"listed"}
JSON
agentcapsule budget create --file - <<'JSON'
{"alias":"support-model","period":"day","limit_tokens":50000,"mode":"hard"}
JSON
agentcapsule template publish --file - --idempotency-key support-rev-1 <<'YAML'
name: support
system_image: ubuntu@1
harness: {name: starter, version: 1.0.0}
resources: {vcpus: 1, memory_mib: 256, data_volume_mib: 128}
capabilities: []
YAML
plan=$(agentcapsule deployment plan --template support@1 --count 3 --active-count 1 \
  --idempotency-key support-batch-1 | jq -er '.data | select(.admitted) | .id')
agentcapsule deployment apply --plan "$plan" --idempotency-key apply-support-1
agentcapsule operation wait --type deployment "$plan"
agentcapsule pool create assistants --deployment "$plan" --idempotency-key pool-assistants
```

The starter echoes text. For inference use an imported model-capable harness, request `llm.invoke` in its template's `capabilities` and select `llm_profile: support-model`. The worker resolves the alias, checks the agent grant and budget, then contacts the selected endpoint. Use `alias grant` or `alias revoke` for an individual agent. `provider rotate PROVIDER_ID --secret-file PATH` replaces that provider's private key. Give a dedicated provider its own alias when it needs an independent key. Check the catalog with `host diagnose llm --organization ORG_ID --alias support-model`, then verify a generation with an assigned member's `agent invoke AGENT_ID --file request.json`, `operation wait --type invocation INVOCATION_ID`, `invocation result INVOCATION_ID` and `llm usage`.

## Register MonApp and verify Alice's access

MonApp is the example client application for the fictional organization Acme. In this scenario a member signs in to MonApp and can use a personal assistant and the team's shared Support assistant. Substitute your application's name, issuer and callback URI when configuring your own environment. The command-line acceptance client exercises this user journey over HTTPS. [Acceptance client](../examples/monapp/verify.py)

Configure the issuer, client and exact redirect URI. Put the registration document in `monapp.yaml` and the policy in `arrival.yaml`. Use the real pool, shared agent and team IDs. Give the backend access to the private registration output. Hand the developer the output of `app connection` after applying the policy. It includes the API origin, discovery URL, audience, client ID, redirects, PKCE method and authorized policy references. [Registration and policy examples](api/applications.md) · [Installation realm](../deploy/oidc/README.md)

```sh
agentcapsule app register monapp --config monapp.yaml --output-file monapp-backend.json
app=$(jq -er '.data.id' monapp-backend.json)
policy=$(agentcapsule assignment-policy plan --file arrival.yaml | jq -er '.data.id')
agentcapsule assignment-policy apply --plan "$policy"
agentcapsule app verify "$app" --issuer-ca oidc-ca.pem
agentcapsule app connection "$app" --output-file monapp-public.json
agentcapsule access explain --member "$alice" --agent "$shared_agent"
```

Run `app verify APP_ID` in the organization's context after registration or rotation. It reads the registration from that installation, fetches the issuer's HTTPS discovery document and checks each pinned RS256 signing key against the published JWKS. A disabled registration, a changed key or an explicitly incompatible code flow or PKCE method fails the check. Supply `--issuer-ca` for a private issuer CA, or omit it for the operating system's trust store. The API and issuer may use different CAs. A provider can omit its optional PKCE metadata, in which case the result reports `advertised_pkce: unadvertised`. Use the member sign-in scenario below to verify an actual token's audience, claims and the client's registered callback. `app show` and `app connection` remain available for inspecting a disabled registration.

The HTTP guide covers inviting Alice and Bob, concurrent acceptance, private results, changing teams, and departure. A new activation can be followed with `operation wait --type activation --app APP_ID ACTIVATION_ID`. On departure, read the admitted-work counts and follow any returned revocation ID with `revocation show ID` under an audit-authorized identity. The current primary enforces the change immediately. The receipt records whether the authority replica has confirmed it. Rotate the backend token with `app rotate APP_ID --output-file monapp-next.json` or revoke the whole integration with `app revoke APP_ID`. [HTTP scenario and runner](api/applications.md)

## Diagnose and maintain

| Observation | Command | What to check |
|---|---|---|
| Readiness, queue and storage | `status --watch`, `doctor` in a platform context | Host sample age, storage pressure, failing jobs and the next check |
| Host-level service state | `host diagnose alerts`, `host diagnose metrics --service worker` | systemd transitions and current Prometheus samples |
| Container images after an install or update | `host diagnose images` | Check `verified` and each service's container state, immutable image ID and expected OCI configuration digest. The schema initializer must have exited with code zero. |
| Filtered service events | `host diagnose journal --service api --request-id ID` | Timestamp and event names for the request |
| Held or delayed exchange | `communication explain RECIPIENT_AGENT REQUEST_ID` | Directory state, visibility at submission, current mandate, consent, outward delivery, attempts and return delivery |
| Backup status | `host diagnose backups` | Repository status and latest successful backup time |
| Export for support | `support export --output-file report.tar.gz` | Versioned aggregate `diagnostics.json` with an observation timestamp |
| Deploy a new guest revision | `rollout start DEPLOYMENT --template support@2 --max-unavailable 1` | `rollout members ID` reports requested and last verified revisions. Fix a canary failure and run `rollout resume ID` |
| Change data volume size | `agent grow AGENT_ID --size-mib 192` | Follow `operation show --type volume-growth ID` for the archive, restore and stage |
| Update the server or recover | `update plan`, `update apply`, `host operation wait`, `restore test`, `restore apply` | Verify the backup repositories and maintenance results in the host operation |

## Script contract

Remote commands emit one JSON object with `version: 1`, `observed_at`, `data` and, when available, the context and HTTP request ID. Watch mode emits one object per line. The host helper uses the separate `agentcapsule.host/v1` schema. `--json` and `--non-interactive` are suitable for unattended jobs. `agentcapsule help` lists the named routes. A raw JSON API request uses `api METHOD /v1/path`. The release binary checks the API major version and CLI wire protocol before sending a credential.

Use `--file PATH`, `--config PATH` or `--file -` for JSON or a single YAML object. Store private inputs in a restricted file or send them on standard input. Commands issuing credentials require an unused `--output-file`. Mutations identify their destination and idempotency key on standard error. Retain that key to retry the same operation after a network interruption. Personal keys and context files belong to the local user. Set `AGENTCAPSULE_CONFIG_DIR` to an absolute private directory to isolate an automation environment.

| Exit code | Meaning |
|---|---|
| 0 | Command completed successfully, or a requested read returned the recorded state |
| 1 | Local configuration, transport or host helper failed |
| 2 | Invalid remote CLI syntax |
| 3 | API returned 401 or 403 |
| 4 | Other HTTP refusal, including quota conflict or an invisible resource |
| 5 | A followed operation failed, expired or paused |
| 130 | Interrupted while waiting |

The storage, wire protocol and binary release each carry their own version. The server verifies the complete PostgreSQL migration ledger on startup. The host update operation performs schema migration within its maintenance window. Use the tested restore path when an older binary cannot read the installed schema. [Host update](cli-host.md#update-and-recovery) · [Recovery](recovery.md)

## Acceptance checks

| Actor and transport | Commands or HTTP action | Observable result |
|---|---|---|
| Linux host administrator, locally or over SSH | `install`, `host operation resume`, `host operation wait` | An invalid signature stops activation. Resumption keeps the existing authorities. The installed worker returns the starter's echo after a restart. [Host guide](cli-host.md) |
| Platform operator, HTTPS | `login`, `session renew`, `organization create`, `quota set` | The enrollment works once, renewal invalidates the old token, and Acme's owner can sign into a separate context. [CLI entry-point test](../cmd/agentcapsule/session_linux_test.go) |
| Organization administrator, HTTPS | `template publish`, `deployment plan`, `deployment apply`, `pool create` | Over-quota batches reserve nothing. An interrupted admitted batch resumes with one encrypted volume per agent. [Database and KVM measurements](api/deployments.md#measured-deployment-on-wsl2-with-kvm) |
| Organization administrator and assigned member, HTTPS | `registry import`, `alias grant`, `agent invoke`, `invocation result` | Import reaches READY. The member gets a response from the chosen model and the provider usage reflects it. [LLM API](api/llm.md) |
| Application owner, backend and members, HTTPS | `app register`, `assignment-policy apply`, then invite, accept, invoke and change membership | Alice and Bob retain distinct personal agents across retries. Bob cannot read Alice's response, and Alice loses team access after transfer. [Reference client and expected results](api/applications.md) |
| Organization administrator and platform operator, separate HTTPS contexts | `communication explain`, `doctor`, `support export` | The organization sees the reason for a held request. The platform archive contains aggregate worker observations and respects the content boundary. [Support archive test](../cmd/agentcapsule/status_test.go) |
| Organization administrator, HTTPS | `rollout start`, `rollout resume`, `agent grow` | A bad canary pauses the update. Resumption reports authenticated boots on the new revision, and restored data survives an offline disk expansion. [Rollouts and volume growth](api/deployments.md#updating-a-deployed-template) |
| Linux host administrator and CLI operator | `update apply`, `restore test`, `restore apply`, `self update` | The updated services can invoke an agent. Recovery preserves revocations and personal volume ownership. The CLI reports its new version after replacement. [Recovery procedure](cli-host.md#update-and-recovery) |
