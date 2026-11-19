# Install and operate a single host

Download the CLI for your OS and architecture from the selected GitHub release.
Verify its digest against the signed `SHA256SUMS` before renaming it to
`agentcapsule`. The release guide gives the exact cosign certificate identity,
issuer and provenance checks. [Release verification](release.md#verify-a-release)

The target is Ubuntu 24.04 amd64 with systemd, cgroup v2, KVM and persistent
local storage. Run the command as root on the target, or pass
`--ssh USER@HOST` from Linux, macOS or Windows. SSH uses the operator's SSH
configuration, known host keys and non-interactive sudo on the target. SSH
host aliases and all profile paths refer to the selected target.

```sh
agentcapsule install --to v0.1.0-rc.1 --profile /root/platform.json --plan-only
agentcapsule install --to v0.1.0-rc.1 --profile /root/platform.json
agentcapsule host operation show host_ID
agentcapsule host operation wait host_ID
agentcapsule host operation resume host_ID
```

The first two commands identify the same operation. The helper records its
input, checkpoints and outcome under `/var/lib/agentcapsule-install`. The
systemd instance continues after SSH disconnects and resumes after reboot.
On a failed phase read `journalctl -u agentcapsule-host@host_ID`, fix the
reported component, and resume. If the CLI itself contains a fix for the
failed phase, add `--refresh-helper` to resume using that verified CLI. All operations emit `agentcapsule.host/v1`
JSON. The operation returns distinct evidence for service startup, the
starter microVM's echo and backups. The probe uses a dedicated organization,
member and encrypted volume. Repeated updates use the same probe agent.

During an update, the host closes the API and keeps the worker available to finish active operations and immediately due invocations. Future scheduled invocations stay in PostgreSQL. Once the worker has stopped and the queue has been checked again, a separate marker holds the worker, authority and private services through offline migration. Both markers survive reboot. The host opens API admissions after the worker and identity provider return.

## Profile

An empty JSON object selects local PostgreSQL 16 on port 55432, a stand-alone
authority, private Directory and SLIM services, HTTPS with a generated local
certificate, and the public starter harness carried by the signed guest.
The probe reserves one agent with one vCPU, 256 MiB RAM and 128 MiB disk.
The normal profile provisions Keycloak and a dedicated realm database in the
same PostgreSQL cluster. Its HTTPS issuer defaults to port 9444. The PaaS
API defaults to 9443. Directory listens on loopback port 8443.

```json
{
  "schema": "agentcapsule.install/v1",
  "api_name": "agents.acme.example",
  "host_id": "worker-01",
  "platform_account": "operator-alice",
  "storage_mib": 32768,
  "max_active": 4,
  "tls_certificate": "/root/pki/api-chain.pem",
  "tls_key": "/root/pki/api-key.pem",
  "tls_ca": "/root/pki/ca.pem",
  "oidc_name": "identity.acme.example",
  "oidc_cert": "/root/pki/identity-chain.pem",
  "oidc_key": "/root/pki/identity-key.pem",
  "oidc_ca": "/root/pki/ca.pem",
  "monapp_redirect_uri": "https://monapp.acme.example/login/callback",
  "allow_internal_providers": ["models.acme.example:11434"]
}
```

`database_url_file` selects an existing PostgreSQL role and database for
the PaaS. Supply the DSN in a root-owned 0600 file. The API and worker apply
their usual TLS policy. `registry_rules` sets the worker's existing registry
rules. `interop_certs` selects a prepared Directory/SLIM PKI directory.
`first_uid` and `last_uid` select the dedicated jailer UID range.

The initial platform enrollment proof is in
`/etc/agentcapsule/first-enrollment.token` (0600). Transfer it to the named
operator through a private channel. It expires after 15 minutes and can be
redeemed once. Keep the API certificate or its CA with the CLI context.
Keycloak bootstrap credentials are in `/etc/agentcapsule/oidc.env` (0600).
The realm and discovery URL are described in the identity provider guide.
[OIDC provider](../deploy/oidc/README.md)

See the backup guide for the two encrypted repositories, off-host credentials
and volume shipping. Provide `pgbackrest_config` and `rclone_config` in the
installation profile. A missing destination is reported in the install
result. The single-host authority can be paired to a replica using the
recovery procedure. Verify custody of the receipt key, transit keys and
authority recovery material independently. [Recovery](recovery.md)

## Verify and load offline assets

On the connected station obtain `agentcapsule-bundle.json`, the server bundle,
package tar, OCI image archive, `SHA256SUMS`, `SHA256SUMS.sigstore.json` and the pinned cosign Linux
binary under the name `cosign-linux-amd64`. Copy these files onto the target. The CLI embeds the Sigstore trusted root
whose verified TUF target SHA-256 is
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
Use `--trusted-root` to select an independently trusted replacement. The CLI
checks the verifier's pinned digest and the workflow identity for the exact
tag. It verifies the archive digests and checks every extracted server file
against the signed inventory. A resumed update rechecks its prepared server
directory before using its dependencies and activating the release. The package tar holds
the APT dependency closure. The image archive uses the immutable manifest
references and the runtime verifies the loaded image's config digest.
Preflight checks the OS, cgroup controllers and KVM before large downloads.

```sh
agentcapsule install --offline /srv/rc1 --trusted-root /root/trusted_root.json --to v0.1.0-rc.1
```

Local development builds accept `--development-key /root/dev.pub` with
`--offline` and an explicit `vX.Y.Z-dev.N` tag. Their `SHA256SUMS.dev.sig`
is an Ed25519 signature over `SHA256SUMS`, generated by
`openssl pkeyutl -sign -rawin -inkey dev.key -in SHA256SUMS -out SHA256SUMS.dev.sig`.
The private build trust remains tied to this installation. Official tags use
the GitHub workflow certificate.

## Update and recovery

```sh
agentcapsule update check
agentcapsule update plan --to v0.1.0
agentcapsule update apply --plan host_ID
agentcapsule host operation wait host_ID
agentcapsule self update --to v0.1.0
agentcapsule archive --agent agt_ID --archive-id arc_ID
agentcapsule restore test --agent agt_ID --archive-id arc_ID
agentcapsule restore apply --agent agt_ID --archive-id arc_ID --restore-id rst_ID
```

The PaaS updater first prepares and verifies artifacts and a full backup.
Current server bundles include the migration names and SQL checksums exported
by the candidate admin binary, including the baseline schema. During an update,
the CLI compares that signed history with PostgreSQL before downloading the
server archives. The plan reports `database_ledger_verified` when the installed
rows match. An older candidate can report `migration_filenames`, with the SQL
checksum check deferred to the database migration. An incompatible service
protocol or migration mode stops the plan.
It closes admissions, waits for existing work, stops affected services,
switches the installation symlink, applies the new binary's exact schema
history, and sends an invocation. The worker retains the configured kernel,
VMM and initrd paths of its existing guests. A failed migration leaves a
named operation to resume. Inspect the migrated data format and protocols
before reverting a binary. A restore uses the current authority and durable
restore ID and retains destruction and revocation state. The service
returns the observed result of the restore. The SQL database also holds the
OIDC realm when both are on the managed cluster. [Recovery](recovery.md)

The CLI updater verifies the signed digest for its own OS and architecture
using the operator's cosign installation, then stages the replacement beside
the current executable. Offline CLI updates take the same `--offline`,
`--trusted-root` and `--to` options.

The archive and restore-apply commands stop the maintenance worker while the
one-shot operator process owns its listeners. They resume it when it was
previously running. A restore test runs beside the worker and reports its
archive digest, size and authority checks in the operation's storage result.
When restoring the installation's starter agent, add `--verify-starter` to
`restore apply`. The operation submits a fresh echo request after restoring
the volume and records the agent and invocation IDs. If the echo fails, a
resume retries that check from the completed restore checkpoint.

To qualify two signed builds on a dedicated instance, the repository provides
`scripts/verify-cli-host.py`. Pass the two asset directories and versions, the
CLI, an installation profile with backup repositories and a command that
reboots only that instance. The report records the guest boot IDs during the
interrupted installation and after the upgrade, the recovered checkpoints,
the encrypted-volume checks and a fresh invocation on the restored agent.

Run `agentcapsule host diagnose images` to compare the service containers with the active release's image inventory. The report names each service and its immutable image ID. With Docker's containerd image store, the helper exports the image by that ID to a temporary file and checks the OCI configuration digest inside it. The disk space is released after each image. The qualification checks this report after installation and again after the upgraded guest reboots.

### Development qualification on WSL2

On 19 November 2026, a network-isolated Ubuntu 24.04 instance in WSL2 installed the development assets offline and booted Firecracker on KVM. Resuming the interrupted installation preserved the original operation. The API verified the starter's echo and pgBackRest verified full encrypted backups in two local repositories. The host reported `off_host_backup_verified: false` for those destinations.

The operator upgraded the server from `v0.1.0-dev.2` to `v0.1.0-dev.4`. PostgreSQL applied migrations 53 and 54, and the original probe agent returned a new echo. The `v0.1.0-dev.5` Linux CLI resumed the operation after fixing the Keycloak service restart. The realm's HTTPS discovery document was available again after a second, explicit service restart.

MonApp's HTTP acceptance client then used the installed API, Keycloak and worker. The test provisioned three agents for Alice and Bob, checked the response from the starter harness, enforced the private-result boundary and confirmed Alice's revocation. [Application scenario](api/applications.md) · [KVM batch measurements](api/deployments.md#measured-deployment-on-wsl2-with-kvm)

After the upgrade, the Ubuntu instance booted again from its existing disk. The test recorded a different guest boot ID, confirmed API and OIDC readiness over HTTPS and received a fresh echo from the original agent. The CLI archived its 128 MiB encrypted volume locally. `restore test` verified the manifest, digest, volume, copy and key. `restore apply` advanced the volume from incarnation 1 to 2 and reported zero lost outcomes. The same agent then answered a new invocation from the restored volume.

On 19–20 November, the same instance upgraded from `v0.1.0-dev.4` to the signed `v0.1.0-dev.6` server. The `dev.7` Linux CLI compared all 54 migration records with the live PostgreSQL ledger before applying the update. Both encrypted local backup sets passed verification. The original starter agent returned a fresh echo after activation.

The runtime check identified the containers for Directory, HAProxy, OASF, SLIM and Keycloak, plus the OASF schema initializer that exited successfully. The Docker containerd store returned `sha256:fd4266fc…` for Directory's image and `sha256:aa27974a…` for its OCI configuration. Exporting the running container’s immutable image verified that configuration against the signed media. The engine reported the same 15 ordered layer digests as the media. On the upgraded server, the CLI restored the original 128 MiB volume from incarnation 2 to 3, reported zero lost outcomes and received another echo from the same agent. The guest reboot reported above was on `dev.4`. [Signed development media](release.md#signed-linux-development-build-v010-dev6) · [Candidate image qualification](release-image-qualification.md)

MonApp then repeated the Alice and Bob scenario on the installed `dev.6` API and Keycloak 26.8.2. The CLI verified the registered issuer's published RS256 key and both members signed in using authorization code with S256 PKCE. The HTTP client exercised two distinct personal agents, their shared Support agent, private result access and the effect of Alice's departure. The CLI rotated the application's provisioning credential, revoked the registration and verified that the revoked registration failed its check. The run disabled its test organizations and removed its temporary Keycloak realm. [MonApp HTTP acceptance scenario](api/applications.md)
