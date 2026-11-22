# Install and operate a single host

Download and verify the workstation CLI for the release you want, for example
with the release's installer:

```sh
curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/download/v0.0.1/install.sh | sh -s -- --version v0.0.1
```

Run `agentcapsule version` and `agentcapsule install --help` on that workstation.
The released CLI uses its own tag to locate the server bundle on GitHub.
Use `--to TAG` to select another exact release. [Download and verify the CLI](release.md#verify-a-release)

The target is Ubuntu 24.04 amd64 with systemd, cgroup v2, KVM and persistent
local storage. Run the command as root on the target, or pass
`--ssh USER@HOST` from Linux, macOS or Windows. SSH uses the operator's SSH
configuration, known host keys and non-interactive sudo on the target. SSH
host aliases come from the workstation configuration. The profile and offline
asset paths refer to files on the selected target.

```sh
agentcapsule install --ssh admin@host --profile /root/platform.json --plan-only
agentcapsule install --ssh admin@host --profile /root/platform.json
agentcapsule host operation wait host_ID --ssh admin@host
```

The plan verifies the signed release metadata. The second command returns the
same `operation_id` and starts installation. Use that ID in place of
`host_ID` to wait for the result. Omit `--profile` to use the defaults
described below. The helper records its
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

The local cluster has three roles ([install.md](install.md#postgresql)):
`agentcapsule` owns the database and runs the migrations, as root;
`agentcapsule_api` and `agentcapsule_worker` own nothing and write only what
the API and the worker write. `pg_ident.conf` maps root to the owner and to
the worker's role, and the API's account to the API's role only. Each unit's
file in `/etc/agentcapsule` (`api.env`, `worker.env`) names its own role;
`admin.env` (0600) names the owner, for `agentcapsule-admin`. An update of an
installation that still connects every service as the owner creates the two
roles, rewrites both maps and both files, then migrates.

`database_url_file` selects an existing PostgreSQL role and database for
the PaaS: the owner's, which migrates. `api_database_url_file` and
`worker_database_url_file` give the API's and the worker's, and are required
with it: create those roles before the installation migrates. Supply each DSN
in a root-owned 0600 file. The API and worker apply their usual TLS policy. `registry_rules` sets the worker's existing registry
rules. `interop_certs` selects a prepared Directory/SLIM PKI directory.
`first_uid` and `last_uid` select the dedicated jailer UID range.

The initial platform enrollment proof is in
`/etc/agentcapsule/first-enrollment.token` (0600). Transfer it to the named
operator through a private channel. It expires after 15 minutes and can be
redeemed once. Keep the API certificate or its CA with the CLI context.
Keycloak bootstrap credentials are in `/etc/agentcapsule/oidc.env` (0600).
Keycloak listens on loopback only: its public port is served by
`agentcapsule-oidc-edge`, which forwards the realms' pages and endpoints and
nothing of the administration. Reach the administration console through SSH
(`ssh -L 9445:127.0.0.1:9445 admin@host`, then `http://localhost:9445/admin/`),
create a permanent administrator with the master realm's `admin` role, then
run `agentcapsule host oidc retire-bootstrap-admin --ssh admin@host`: it
deletes the bootstrap administrator and its two entries, and refuses while no
other administrator exists. Each install and update does the same on its own
once a permanent administrator exists, and turns on brute-force detection in
the master realm and the platform's (the operation's `oidc_bootstrap_admin`
says `kept` or `retired`). The realm and discovery URL are described in the
identity provider guide. [OIDC provider](../deploy/oidc/README.md)

See the backup guide for the two encrypted repositories, off-host credentials
and volume shipping. Provide `pgbackrest_config` and `rclone_config` in the
installation profile. Start `pgbackrest_config` from
[deploy/backup/pgbackrest.conf](../deploy/backup/pgbackrest.conf): its `pg1-`
lines already name the installer's cluster (`16/agentcapsule`, port 55432).
A missing destination is reported in the install
result. The single-host authority can be paired to a replica using the
recovery procedure. Verify custody of the receipt key, transit keys and
authority recovery material independently. [Recovery](recovery.md)

## Verify and load offline assets

For a private release or an offline target, download the host assets on a
connected workstation with an existing GitHub CLI login authorized to read the
release. Set `tag` to the verified CLI's release tag. Use an empty directory.

```sh
gh release download "$tag" --repo ArnaudGuiovanna/agentcapsule --dir assets \
  -p agentcapsule-bundle.json -p agentcapsule-server-linux-amd64.tar.gz \
  -p agentcapsule-packages-linux-amd64.tar -p agentcapsule-images-linux-amd64.tar.gz \
  -p cosign-linux-amd64 -p SHA256SUMS -p SHA256SUMS.sigstore.json
```

Copy the seven files to one directory on the Ubuntu target, for example
`/srv/agentcapsule-release`. The CLI embeds the Sigstore trusted root
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
agentcapsule install --ssh admin@host --offline /srv/agentcapsule-release --to "$tag" --plan-only
agentcapsule install --ssh admin@host --offline /srv/agentcapsule-release --to "$tag"
```

Local development builds accept `--development-key /root/dev.pub` with
`--offline` and an explicit `vX.Y.Z-dev.N` tag. Their `SHA256SUMS.dev.sig`
is an Ed25519 signature over `SHA256SUMS`, generated by
`openssl pkeyutl -sign -rawin -inkey dev.key -in SHA256SUMS -out SHA256SUMS.dev.sig`.
The private build trust remains tied to this installation. Official tags use
the GitHub workflow certificate: the release workflow of the tag, run by the
push of that tag in this repository, in the protected `release` environment
([release.md](release.md#the-release-environment)).

**No downgrade (L-13).** The host records the highest release it has
installed (`/var/lib/agentcapsule-install/highest-release.json`). An install
or an update to an older release is refused, and so is the install, on an
empty host, of a release older than the CLI's own; `--allow-older` on
`install` or `update plan` overrides both. A rollback (`rollback plan`) is the
way back to an older release and does not lower the record. The "latest"
release that the CLI reads from GitHub, without authentication, is subject to
the same floor.

## Update and recovery

```sh
agentcapsule update check
agentcapsule update plan --to v0.1.0
agentcapsule update apply --plan host_ID
agentcapsule rollback plan --to v0.1.0-rc.1
agentcapsule rollback apply --plan host_ID
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
named operation to resume. A restore uses the current authority and durable
restore ID and retains destruction and revocation state. The service
returns the observed result of the restore. The SQL database also holds the
OIDC realm when both are on the managed cluster. [Recovery](recovery.md)

### Rolling PostgreSQL upgrades

On a shared PostgreSQL installation, an admin can apply an expand migration
while API and worker processes from the preceding build continue to serve.
Deploy the first build with migration 0084 using the maintenance procedure
above. Earlier binaries require their exact ledger. After that upgrade:

1. Back up the installation and compare the signed migration manifests. An
   expand preserves the reads and writes of both builds. Apply it with the
   candidate admin's `migrate` command.
2. Check readiness on the old and new services, then replace API and worker
   processes one host at a time. A signed host plan reports
   `database_expand_verified` if another host has already applied the
   candidate's compatible prefix. The host updater still drains its local
   services before replacing them.
3. Drain every older process before a contract migration. An older service
   refuses readiness at the first undeclared or incompatible row. An admin
   always requires its complete known history before managing the schema.
   The host binary rollback checks below continue to cover the entire release.

Migration authors declare compatibility with `-- agentcapsule:expand` on
the first line of the SQL file. Each expand commits separately and shares the
application's store gate. Use a later contract to remove old fields or enforce
constraints that older writers cannot meet. Migrations without a declaration
take the exclusive gate. Keep the historical SQL and its checksum intact.

For a large existing table, put a plain B-tree index in its own migration.
Use the first line `-- agentcapsule:expand-index`, followed by one statement
such as `CREATE INDEX CONCURRENTLY jobs_by_state ON jobs (state, id);`.
The admin waits for active writers and the entire build. Interrupting the
command releases its session and leaves the ledger at the last committed step.
This form accepts ordinary lowercase identifiers and named columns in default
order. A retry checks PostgreSQL's index definition, keeps a completed build
and rebuilds an interrupted one. More complex index definitions require
a reviewed online migration procedure or a maintenance window.

Use `rollback plan --to TAG` to select an older release. An eligible plan
reports `binary_rollback_compatible: true` and `database_ledger_verified`.
The active build must have an authenticated activation receipt. Both signed
builds must identify the same platform state and authority compatibility epoch,
server protocol, complete SQL history, host packages, OCI images, service
definitions, guest kernel, initrd, VMM and jailer. The helper verifies each
tag's signing identity and requires the same signing authority across the
switch. For locally signed development builds, pass `--offline` and
`--development-key` to the plan. Apply takes its operation ID.

The rollback operation verifies the candidate, makes the configured off-host
backup, closes admissions, drains the workers and checks the live SQL history
again. It switches the active binary directory and opens services using
their existing configuration, authority identities, volume ownership and
revocation records. The operation then verifies the original starter agent.
A late data-format refusal reopens the source release. Inspect a failed
operation with `host operation show` before resuming it. Plans are bound to
one activation, including when a later transition returns to the same tag.

When either signed build lacks the format declaration, a dependency differs
or the database has already migrated beyond the candidate, the plan refuses
the binary switch. Select a coordinated PostgreSQL and volume recovery point
and use the current independent authorities to retain destroyed keys and
revocations. Writes made after the chosen recovery point may be lost.
[Restore procedure and recovery window](recovery.md)

The CLI updater verifies the signed digest for its own OS and architecture
using the operator's cosign installation, with the same signer checks as the
host, then stages the replacement beside the current executable. Offline CLI
updates take the same `--offline`, `--trusted-root` and `--to` options. It
refuses a release older than the running CLI or than the highest release it
has installed, recorded in `self-update.json` of the CLI's configuration
directory, unless `--allow-older` is given.

**Certificates (L-14).** The certificates the installer generates (the API's,
the identity provider's when no `oidc_cert` is given, and the private
services' when no `interop_certs` is given) last 365 days. Each update renews
those that expire within 30 days: the API's and the identity provider's keep
their keys, the private services get new authorities. The configure phase
lists them in `renewed_certificates`. A renewed self-signed API certificate
must be given again to the clients that pin it (`context add --ca`).
`agentcapsule host diagnose certificates` reports, for every certificate,
its expiry, the days left, `ok`, `renewal_due` or `expired`, and whether an
update renews it (`update`) or the operator does (`operator`).

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

On 20 November, the same Ubuntu instance upgraded from `dev.6` to `dev.12`. The test verified the media signature and all 45 payloads, then signed the identical index with the development key already trusted by the instance. After the upgrade, the live PostgreSQL ledger matched all 55 signed migration records and both local backup sets passed verification. Ubuntu rebooted from the same disk, the WSL host kept its boot ID, and the original starter answered a new invocation. The CLI checked all six service images against the installed release. [Signed dev.12 media](release.md#signed-linux-development-build-v010-dev12)

On the upgraded instance, the CLI resized a standalone agent from 1 vCPU and 256 MiB to 2 vCPUs and 384 MiB. The test read the running Firecracker configuration and verified that generation 3 answered with the same encrypted 128 MiB volume. In a separate check, the CLI archived and restored the original starter's volume. Its incarnation advanced from 3 to 4, the restore reported zero lost outcomes, and the same starter answered a fresh invocation.

The final MonApp HTTP run provisioned three agents and authenticated Alice and Bob through Keycloak. It verified private result access, confirmed Alice's revocation after departure, and revoked the application's registration. The run disabled its two test organizations and removed its temporary Keycloak realm. All seven checks passed on `dev.12`. Both PostgreSQL backup repositories remained on the same physical host. [CLI progress](plan-cli.md#suivi-du-chantier)
